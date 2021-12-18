from scapy.all import *
from scapy.layers import *
from hell_capture_using_scapy import HellCapture
import sys

def sniff_packets(self, iface=None):
        hc = HellCapture()
        print('sniffing...')
        if iface:
            pkt = sniff(session=TCPSession, iface=iface, prn=hc.process_packet)
        else:
            # sniff with default interface
            pkt = sniff(session=TCPSession, prn=hc.process_packet, store=False)

def main():
    # driverの起動
    
    # interface選択
    # iface = None
    # if '--iface' in sys.argv:
    #     show_interfaces()
    #     index = input('select index: ')
    #     iface = dev_from_index(index)
    
    hc = HellCapture()
    print('sniffing...')
    request_pkt = None
    response_pkt = None
    while(request_pkt is None):
        request_pkt = sniff(session=TCPSession, lfilter=lambda pkt: hc.request_filter(pkt), count=1)[0]
    print(request_pkt.show())

    while(response_pkt is None):
        response_pkt = sniff(session=TCPSession, lfilter=lambda pkt: hc.response_filter(pkt, request_packet=request_pkt), count=1)
    print(response_pkt.show())



    sniff_packets(iface)

if __name__ == "__main__":

    main()