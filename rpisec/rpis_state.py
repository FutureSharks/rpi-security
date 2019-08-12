# -*- coding: utf-8 -*-

import logging
from datetime import timedelta
from threading import Lock
import time


logger = logging.getLogger()


class RpisState(object):
    '''
    Contains state information about the alarm and handles updates
    '''
    def __init__(self, rpis):
        self.rpis = rpis
        self.lock = Lock()
        self.start_time = time.time()
        self.current = 'disarmed'
        self.previous = 'Not running'
        self.last_change = time.time()
        self.last_packet = time.time()
        self.last_mac = None
        self.triggered = False

    def update_state(self, new_state):
        assert new_state in ['armed', 'disarmed', 'disabled']
        if new_state != self.current:
            with self.lock:
                self.previous = self.current
                self.current = new_state
                self.last_change = time.time()
                self.rpis.telegram_send_message("rpi-security is now {0}".format(self.current))
                logger.info("rpi-security is now {0}".format(self.current))

    def update_triggered(self, triggered):
        with self.lock:
            self.triggered = triggered

    def update_last_mac(self, mac):
        with self.lock:
            self.last_mac = mac
            self.last_packet = time.time()

    def _get_readable_delta(self, then):
        td = timedelta(seconds=time.time() - then)
        days, hours, minutes = td.days, td.seconds // 3600, td.seconds // 60 % 60
        text = '{0} minutes'.format(minutes)
        if hours > 0:
            text = '{0} hours and '.format(hours) + text
            if days > 0:
                text = '{0} days, '.format(days) + text
        return text

    def check(self):
        if self.current == 'disabled':
            return
        now = time.time()
        if now - self.last_packet > (self.rpis.packet_timeout + 20):
            if self.current != 'armed':
                logger.debug("No packets detected for {0} seconds, arming".format(self.rpis.packet_timeout + 20))
            self.update_state('armed')
        elif now - self.last_packet > self.rpis.packet_timeout:
            logger.debug("Running arp_ping_macs before arming...")
            self.rpis.arp_ping_macs()
        else:
            self.update_state('disarmed')

    def generate_status_text(self):
        return (
            "*rpi-security status*\n"
            "Current state: _{0}_ \n"
            "Last state: _{1}_ \n"
            "Last change: _{2} ago_ \n"
            "Uptime: _{3}_ \n"
            "Last MAC detected: _{4} {5} ago_ \n"
            "Alarm triggered: _{6}_ \n"
            ).format(
                    self.current,
                    self.previous,
                    self._get_readable_delta(self.last_change),
                    self._get_readable_delta(self.start_time),
                    self.last_mac,
                    self._get_readable_delta(self.last_packet),
                    self.triggered
                )
