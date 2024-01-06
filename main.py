import sys
import time
import schedule
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from base64 import b64decode
from pathlib import Path
from typing import List
import yagmail

from gvm.protocols.gmp import Gmp
from gvm.connections import UnixSocketConnection
from gvm.transforms import EtreeTransform

HELP_TEXT = """
        This script makes an E-Mail alert scan.

        Usage examples:
            ... bso-scan.py +h
            ... bso-scan.py ++target-name ++hosts +C +R +S
            ... bso-scan.py ++target-name ++hosts +C ++recipient ++sender
    """


def get_scan_config(gmp: Gmp, config: int, debug: bool = False):
    # get all configs of the openvas instance
    # filter for all rows!
    res = gmp.get_scan_configs(filter_string="rows=-1")

    if config < 0 or config > 4:
        raise ValueError("Wrong config identifier. Choose between [0,4].")
    # match the config abbreviation to accepted config names
    config_list = [
        "Full and fast",
        "Full and fast ultimate",
        "Full and very deep",
        "Full and very deep ultimate",
        "System Discovery",
    ]
    template_abbreviation_mapper = {
        0: config_list[0],
        1: config_list[1],
        2: config_list[2],
        3: config_list[3],
        4: config_list[4],
    }

    for conf in res.xpath("config"):
        cid = conf.xpath("@id")[0]
        name = conf.xpath("name/text()")[0]

        # get the config id of the desired template
        if template_abbreviation_mapper.get(config) == name:
            config_id = cid
            if debug:
                print(name + ": " + config_id)
            break

    return config_id


def get_target(
    gmp,
    target_name: str = None,
    hosts: List[str] = None,
    debug: bool = False,
):
    if target_name is None:
        target_name = "target"
    targets = gmp.get_targets(filter_string=target_name)
    existing_targets = [""]
    for target in targets.findall("target"):
        existing_targets.append(str(target.find("name").text))
    counter = 0
    # iterate over existing targets and find a vacant targetName
    if target_name in existing_targets:
        while True:
            tmp_name = f"{target_name} ({str(counter)})"
            if tmp_name in existing_targets:
                counter += 1
            else:
                target_name = tmp_name
                break

    if debug:
        print(f"target name: {target_name}")


    # integrate port list id into create_target
    res = gmp.create_target(target_name, hosts=hosts, port_list_id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5")
    print(f"New target '{target_name}' created.")
    return res.xpath("@id")[0]


def get_scanner(gmp: Gmp):
    res = gmp.get_scanners()
    scanner_ids = res.xpath("scanner/@id")
    return scanner_ids[1]  # "default scanner"


def create_and_start_task(
    gmp: Gmp,
    config_id: str,
    target_id: str,
    scanner_id: str,
    recipient_email: str,
    debug: bool = False,
) -> str:
    # Create the task
    task_name = f"Quick Scan for {recipient_email}"
    tasks = gmp.get_tasks(filter_string="name{task_name}")
    existing_tasks = tasks.findall("task")

    if existing_tasks:
        task_name = f"Quick Scan for {recipient_email} ({len(existing_tasks)})"
    res = gmp.create_task(
        name=task_name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id
    )

    # Start the task
    task_id = res.xpath("@id")[0]
    gmp.start_task(task_id)

    if debug:
        # Stop the task (for performance reasons)
        gmp.stop_task(task_id=task_id)
        print("Task stopped")

    return task_id, task_name


def wait_for_scan(gmp: Gmp, task_id: str):
    # Warning infinite loop! finishes when scan status is finished
    while True:
        res = gmp.get_task(task_id)
        finished = int(res.xpath("task/report_count/finished")[0].text)
        if finished: break
        # delay to not overload socket
        time.sleep(10)

    return True

def extract_report(gmp: Gmp, task_id: str) -> Path:
    reports = gmp.get_reports()
    index = 0
    for report in reports.findall('report'):
        if report.xpath('report/task/@id')[0] == task_id: 
            report_id = reports.xpath('report/@id')[index]
            break
        index += 1

    pdf_report_format_id = "c402cc3e-b531-11e1-9163-406186ea4fc5"
    response = gmp.get_report(
        report_id = report_id, report_format_id = pdf_report_format_id
    )

    report_element = response.find("report")
    # getting the full content of the report 
    content = report_element.find("report_format").tail

    if not content:
        print("Requested report is empty")
        print("Exiting now")
        sys.exit(1)

    # convert content to ASCII bytes
    binary_base64_encoded_pdf = content.encode("ascii")

    # decode base64
    binary_pdf = b64decode(binary_base64_encoded_pdf)

    # write pdf to file 
    pdf_path = Path(f"/tmp/bso_reports/{task_id}_report.pdf")
    pdf_path.write_bytes(binary_pdf)
    
    print("Done. PDF created: " + str(pdf_path))

    return pdf_path


def send_email(recipient_email: str, sender_email: str, email_password:str,
                pdf_path: Path, task_id: str, task_name: str):
    
    contents = f"""
Task {task_name} with id {task_id} has finished.
This email escalation is configured to attach .pdf report.   

Note:
This email was sent to you as a configured security scan escalation.
Please contact your local system administrator if you think you
should not have received it."""
    
    mail = yagmail.SMTP(sender_email, email_password)

    mail.send(recipient_email, subject="[BSO-Scan] Scan Report", contents=contents, attachments=str(pdf_path))

    print("E-mail succesfully sent!")


def parse_args():  # pylint: disable=unused-argument
    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description=HELP_TEXT,
    )

    parser.add_argument(
        "+h",
        "++help",
        action="help",
        help="Show this help message and exit.",
    )

    parser.add_argument(
        "+i",
        "++interval",
        type=int,
        dest="interval",
        help="Time interval between scans [hours]",
    )

    target = parser.add_mutually_exclusive_group()

    target.add_argument(
        "++target-name",
        type=str,
        dest="target_name",
        help="Create a target by name",
    )

    parser.add_argument(
        "++hosts",
        nargs="+",
        required=True,
        dest="hosts",
        help="Host(s) for the new target",
    )

    config = parser.add_mutually_exclusive_group()

    config.add_argument(
        "+C",
        "++scan-config",
        default=0,
        type=int,
        dest="config",
        help="Choose from existing scan config:"
        "\n  0: Full and fast"
        "\n  1: Full and fast ultimate"
        "\n  2: Full and very deep"
        "\n  3: Full and very deep ultimate"
        "\n  4: System Discovery",
    )

    parser.add_argument(
        "+R",
        "++recipient",
        required=True,
        dest="recipient_email",
        type=str,
        help="Alert recipient E-Mail address",
    )

    parser.add_argument(
        "+S",
        "++sender",
        required=True,
        dest="sender_email",
        type=str,
        help="Alert senders E-Mail address",
    )

    script_args, _ = parser.parse_known_args()
    return script_args


def main(gmp: Gmp, args: Namespace, email_password: str) -> None:
    # pylint: disable=undefined-variable, unused-argument

    script_args = args

    recipient_email = script_args.recipient_email
    sender_email = script_args.sender_email

    # use existing config from argument
    
    config_id = get_scan_config(gmp, script_args.config)

    # create new target or use existing one from id

    target_id = get_target(
            gmp,
            target_name=script_args.target_name,
            hosts=script_args.hosts
        )

    scanner_id = get_scanner(gmp)


    task_id, task_name = create_and_start_task(
        gmp, config_id, target_id, scanner_id, recipient_email
    )

    print(f"Task started: {task_name}\n")

    print("Scanning in progress...")
    wait_for_scan(gmp, task_id)

    print("Scan finished")
    print('\n')
    
    print("Extracting report")
    pdf_path = extract_report(gmp, task_id)
    print('\n')

    print(f"Sending e-mail with report to {recipient_email}")
    send_email(recipient_email, sender_email, email_password, pdf_path, task_id, task_name)

    print("Task finished\n")
    print('\n')
    print(f"Another task scheduled in {args.interval} hour/s")


def scan_task(username, password, email_password):
    connectionGmp = UnixSocketConnection(path='/tmp/gvm/gvmd/gvmd.sock')
    transform = EtreeTransform()
    with Gmp(connection=connectionGmp,transform=transform) as gmp:
        gmp.authenticate(username, password)
             
        # get the response message returned as a utf-8 encoded string
        main(gmp, args, email_password)

if __name__ == "__main__":
    args = parse_args()

    print("Provide OpenVAS credentials")
    username = input("Username: ")
    password = input("Password: ")

    print(f"Provide required credentials for {args.sender_email}")
    email_password = input("Password: ")

    # initial run before schedule
    scan_task(username, password, email_password)
    schedule.every(args.interval).hours.do(scan_task, 
                                           username=username, password=password, email_password=email_password)
    
    while True:
        schedule.run_pending()
        time.sleep(1)
