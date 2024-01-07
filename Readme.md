# Profinet sniffer/decoder

Python script to sniffs and decodes profinet messages. The mail goal of this project was to get familar with the profinet protocoll.

## useful links:

- [profinet system description](https://www.profibus.com/index.php?eID=dumpFile&t=f&f=51713&token=5e6746cb84a7421d187681a0d9bd545388cb2a5e)
- [simens doc profinet driver](https://support.industry.siemens.com/dl/files/145/109781145/att_1028016/v1/pn_driver_IO-Base_user_programming_interface_en-US.pdf)
- [wireshark profinet implementation](https://gitlab.com/wireshark/wireshark/-/blob/master/plugins/epan/profinet/packet-dcerpc-pn-io.c)
- [felser profinet documentation](https://www.felser.ch/profinet-handbuch/frame_id.html)
- [scapy documentation](https://scapy.readthedocs.io/en/latest/introduction.html)
- [scapy profinet support](https://scapy.readthedocs.io/en/latest/layers/pnio.html)
 
## scapy, network capturing
https://github.com/secdev/scapy (GPL2)


scapy profinet capturing
https://github.com/secdev/scapy/issues/1491

```
from scapy.all import *
from scapy.contrib.pnio import *

f = "udp and port 8892"
f = "ether proto 0x8892"
a = sniff(count=1,filter=f,iface="eth0")
```


## mqtt

paho-mqtt https://github.com/eclipse/paho.mqtt.python