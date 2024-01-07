from scapy.all import *
from scapy.contrib.pnio import *
from scapy.contrib.pnio_rpc import *
from scapy.layers.dcerpc import DceRpc

# f = "udp and port 8892"
# # f = "ether proto 0x8892"
# a = sniff(count=1,filter=f,iface="eth0")

destMac = "00:00:00:00:00:00"
srcMac = "00:00:00:00:00:01"

# add profinet dceRpc port
bind_layers(UDP, DceRpc, dport=34964)
bind_layers(UDP, DceRpc, dport=49152)
bind_layers(UDP, DceRpc, dport=49153)

APIs = {"input": {}, "output": {}}


def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x


rawDataOldDst = bytes()
rawDataOldSrc = bytes()


def callback(packet):
    # if packet.dst != destMac:
    #     return
    # print(list(expand(packet)))
    global APIs
    # PROFINET RT packets
    if "PROFINET IO Real Time Cyclic Default Raw Data" in packet:
        # if packet.type == 0x8892:
        res = list(expand(packet))
        # packet["ProfinetIO"]["PROFINET Real-Time"][
        rawData = packet.getlayer("PROFINET IO Real Time Cyclic Default Raw Data").data
        # packet.show()
        if packet.dst == destMac:
            global rawDataOldDst
            if rawData != rawDataOldDst:
                rawDataOldDst = rawData
                print(parseRawData(APIs, rawData, "output"))
        if packet.dst == srcMac:
            global rawDataOldSrc
            if rawData != rawDataOldSrc:
                rawDataOldSrc = rawData
                print(parseRawData(APIs, rawData, "input"))
        return
    # PNIO‐CM connect
    if "DCE/RPC v4" in packet:  # port UDP 34964
        dceRcp = packet.getlayer("DCE/RPC v4")
        if dceRcp.opnum == 0 and dceRcp.ptype == 0:
            APIs = handleConnectMessage(packet)
        match dceRcp.opnum:
            case 0:
                print("Connect ", end="")
            case 1:
                print("Release ", end="")
            case 2:
                print("Read ", end="")
            case 3:
                print("Write ", end="")
            case 4:
                print("Control ", end="")
            case 5:
                print("Read Implicit ", end="")
        match dceRcp.ptype:
            case 0:
                print("request")
            case 2:
                print("response")
        # layer = packet.getlayer("PNIOServiceReqPDU").blocks
        # packet.show()
        frameId = 1
        api = 0


def parseRawData(APIs, rawData, direction):
    decodedData = dict()
    if len(APIs[direction]) == 0:
        return {direction: rawData}
    for _, api in APIs[direction].items():
        for ioDataObject in api["IODataObjects"]:
            identifier = f"{ioDataObject['SlotNumber']}.{ioDataObject['SubslotNumber']}"
            start = ioDataObject["FrameOffset"]
            end = start + ioDataObject["SubmoduleDataLength"]
            data = rawData[start:end]
            iopsEnd = end + ioDataObject["LengthIOPS"]
            iopsData = rawData[end:iopsEnd]
            decodedData[identifier] = {"data": data, "IOPS": iopsData}
    return {direction: decodedData}


def handleConnectMessage(packet):
    print("Connect ", end="")
    APIs = {"input": {}, "output": {}}
    blocks = packet.getlayer("PNIOServiceReqPDU").blocks
    for block in blocks:
        if block.name == "IOCRBlockReq" and (
            block.IOCRType == 0x0001 or block.IOCRType == 0x0002
        ):  # block type 0x0102 and Input or Output Cr
            for api in block.APIs:
                IOCSs = [d.fields for d in api.IOCSs]
                IODataObjects = [d.fields for d in api.IODataObjects]
                inOrOut = "output"
                if block.IOCRType == 0x0001:
                    inOrOut = "input"
                    # APIs[inOrOut]["frameId"] = block.FrameID
                    # APIs[inOrOut]["srcMac"] = packet.src
                else:
                    # APIs[inOrOut]["srcMac"]=packet.dst
                    pass
                APIs[inOrOut][api.API] = {
                    "IOCSs": IOCSs,
                    "IODataObjects": IODataObjects,
                }
            return
        if block.name == "ExpectedSubmoduleBlockReq":  # block type 0x0104
            for api in block.APIs:
                for submodule in api.Submodules:
                    for dataDescription in submodule.DataDescription:
                        slot = api.SlotNumber
                        subslot = submodule.SubslotNumber
                        dataLength = dataDescription.SubmoduleDataLength
                        lengthIOCS = dataDescription.LengthIOCS
                        lengthIOPS = dataDescription.LengthIOPS
                        # Input IOCR: Input Data Descriptions -> IODataObjects & Output Data Descriptions -> IOCSs
                        # Output IOCR: output Data Descriptions -> IODataObjects & input Data Descriptions -> IOCSs
                        if dataDescription.DataDescription == 0x001:  # input
                            # do input stuff
                            for i, iocs in enumerate(
                                APIs["input"][api.API]["IODataObjects"]
                            ):
                                if (
                                    iocs["SlotNumber"] == slot
                                    and iocs["SubslotNumber"] == subslot
                                ):
                                    APIs["input"][api.API]["IODataObjects"][i].update(
                                        dataDescription.fields
                                    )
                                    break
                            for i, iocs in enumerate(APIs["output"][api.API]["IOCSs"]):
                                if (
                                    iocs["SlotNumber"] == slot
                                    and iocs["SubslotNumber"] == subslot
                                ):
                                    APIs["output"][api.API]["IOCSs"][i].update(
                                        dataDescription.fields
                                    )
                                    break
                        elif dataDescription.DataDescription == 0x002:
                            # do output stuff
                            for i, iocs in enumerate(
                                APIs["output"][api.API]["IODataObjects"]
                            ):
                                if (
                                    iocs["SlotNumber"] == slot
                                    and iocs["SubslotNumber"] == subslot
                                ):
                                    APIs["output"][api.API]["IODataObjects"][i].update(
                                        dataDescription.fields
                                    )
                                    break
                            for i, iocs in enumerate(APIs["input"][api.API]["IOCSs"]):
                                if (
                                    iocs["SlotNumber"] == slot
                                    and iocs["SubslotNumber"] == subslot
                                ):
                                    APIs["input"][api.API]["IOCSs"][i].update(
                                        dataDescription.fields
                                    )
                                    break
    return APIs


if __name__ == "__main__":
    # ifList = get_if_list()
    # print(get_working_ifaces())
    # print(show_interfaces())
    networkInterface = dev_from_index(8)
    # f='src host 192.168.1.1'

    sniff(iface=networkInterface.name, prn=callback)
