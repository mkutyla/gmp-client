from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.latest import Osp

# path to unix socket
connectionGmp = UnixSocketConnection(path='/tmp/gvm/gvmd/gvmd.sock')
connectionOsp = UnixSocketConnection(path='/tmp/osp/ospd/ospd-openvas.sock')

# using the with statement to automatically connect and disconnect to gvmd
with Gmp(connection=connectionGmp) as gmp:
        # get the response message returned as a utf-8 encoded string
    gmp.authenticate("admin","admin")   
    print(gmp.get_reports())
    print('\n')    
# using the with statement to automatically connect and disconnect to gvmd
with Osp(connection=connectionOsp) as osp:
        # get the response message returned as a utf-8 encoded string
    print(osp.get_version())
