# -*- coding: utf-8 -*-

import _thread
import logging
from kamene.all import sniff
from kamene.all import conf as kamene_conf
kamene_conf.promisc=0
kamene_conf.sniff_promisc=0


logger = logging.getLogger()


def capture_packets(rpis):
    """
    This function uses kamene to sniff packets for our MAC addresses and updates
    the alarm state when packets are detected.
    """
    logging.getLogger("kamene.runtime").setLevel(logging.ERROR)
    def update_time(packet):
        packet_mac = set(rpis.mac_addresses) & set([packet[0].addr2, packet[0].addr3])
        packet_mac_str = list(packet_mac)[0]
        rpis.state.update_last_mac(packet_mac_str)
        logger.debug('Packet detected from {0}. State is {1}'.format(packet_mac_str, rpis.state.current))
    def calculate_filter(mac_addresses):
        mac_string = ' or '.join(mac_addresses)
        filter_text = (
            '((wlan addr2 ({0}) or wlan addr3 ({0})) '
            'and type mgt subtype probe-req) '
            'or (wlan addr1 {1} '
            'and wlan addr3 ({0}))'
        )
        return filter_text.format(mac_string, rpis.my_mac_address)
    while True:
        logger.info("thread running")
        try:
            sniff(iface=rpis.network_interface, store=0, prn=update_time, filter=calculate_filter(rpis.mac_addresses))
        except Exception as e:
            logger.error('kamene failed to sniff packets with error {0}'.format(repr(e)))
            _thread.interrupt_main()
