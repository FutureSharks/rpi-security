# -*- coding: utf-8 -*-

import sys
import os
import time
import yaml
import logging

logging.getLogger("kamene.runtime").setLevel(logging.ERROR)

from configparser import SafeConfigParser
from netaddr import IPNetwork
from netifaces import ifaddresses
from kamene.all import srp, Ether, ARP
from telegram import Bot as TelegramBot
from .exit_clean import exit_error
from .rpis_state import RpisState


logger = logging.getLogger()


class RpisSecurity(object):
    """
    Reads and processed configuration, checks system settings and more...
    """
    default_config = {
        'camera_save_path': '/var/tmp',
        'network_interface': 'mon0',
        'packet_timeout': '700',
        'debug_mode': 'False',
        'camera_vflip': 'False',
        'camera_hflip': 'False',
        'photo_size': '1024x768',
        'gif_size': '1024x768',
        'motion_size': '1024x768',
        'motion_detection_threshold': '1000',
        'camera_mode': 'gif',
        'camera_capture_length': '3',
        'telegram_users_number': '1',
        'arp_ping_count': '7',
    }

    def __init__(self, config_file, data_file):
        self.config_file = config_file
        self.data_file = data_file
        self.saved_data = self._read_data_file()
        self._parse_config_file()
        self._check_system()
        self.state = RpisState(self)

        try:
            self.bot = TelegramBot(token=self.telegram_bot_token)
        except Exception as e:
            raise Exception('Failed to connect to Telegram with error: {0}'.format(repr(e)))

        logger.debug('Initialised: {0}'.format(vars(self)))

    def _read_data_file(self):
        """
        Reads a data file from disk.
        """
        result = None
        try:
            with open(self.data_file, 'r') as stream:
                result = yaml.load(stream, Loader=yaml.FullLoader)
        except Exception as e:
            logger.error('Failed to read data file {0}: {1}'.format(self.data_file, repr(e)))
        else:
            logger.debug('Data file read: {0}'.format(self.data_file))
        return result

    def arp_ping_macs(self):
        """
        Performs an ARP scan of a destination MAC address to try and determine if they are present on the network.
        """
        def _arp_ping(mac_address):
            result = []
            answered,unanswered = srp(Ether(dst=mac_address)/ARP(pdst=self.network_address), timeout=1, verbose=False)
            if len(answered) > 0:
                for reply in answered:
                    if reply[1].hwsrc == mac_address:
                        result.append(str(reply[1].psrc))
                        result = ', '.join(result)
            return result

        count = 0

        while count < self.arp_ping_count:
            for mac_address in self.mac_addresses:
                result = _arp_ping(mac_address)
                if result:
                    logger.debug('MAC {0} responded to ARP ping with address {1}'.format(mac_address, result))
                    return
                else:
                    logger.debug('MAC {0} did not respond to ARP ping'.format(mac_address))
            time.sleep(1)
            count += 1

        logger.debug('ARP ping of MACs received no replies')
        return

    def save_telegram_chat_id(self, chat_id):
        """
        Saves the telegram chat ID to the data file
        """
        try:
            # Use a lock here?
            if self.saved_data['telegram_chat_ids']:
                self.saved_data['telegram_chat_ids'].append(chat_id)
            else:
                self.saved_data['telegram_chat_ids'] = [chat_id]

            with open(self.data_file, 'w') as f:
                yaml.dump({'telegram_chat_ids': self.saved_data['telegram_chat_ids']}, f, default_flow_style=False)
        except Exception as e:
            logger.error('Failed to write state file {0}: {1}'.format(self.data_file, e))
        else:
            logger.debug('State file written: {0}'.format(self.data_file))

    def _parse_config_file(self):
        def _str2bool(v):
            return v.lower() in ("yes", "true", "t", "1")

        cfg = SafeConfigParser(defaults=self.default_config)
        cfg.read(self.config_file)

        for k, v in cfg.items('main'):
            setattr(self, k, v)

        self.debug_mode = _str2bool(self.debug_mode)
        self.camera_vflip = _str2bool(self.camera_vflip)
        self.camera_hflip = _str2bool(self.camera_hflip)
        self.photo_size = tuple([int(x) for x in self.photo_size.split('x')])
        self.gif_size = tuple([int(x) for x in self.gif_size.split('x')])
        self.motion_size = tuple([int(x) for x in self.motion_size.split('x')])
        self.motion_detection_threshold = float(self.motion_detection_threshold)
        self.camera_capture_length = int(self.camera_capture_length)
        self.camera_mode = self.camera_mode.lower()
        self.packet_timeout = int(self.packet_timeout)
        self.mac_addresses = self.mac_addresses.lower().split(',')
        self.telegram_users_number = int(self.telegram_users_number)
        self.arp_ping_count = int(self.arp_ping_count)

    def _check_system(self):
        if not os.geteuid() == 0:
            exit_error('{0} must be run as root'.format(sys.argv[0]))

        if not self._check_monitor_mode():
            raise Exception('Monitor mode is not enabled for interface {0} or interface does not exist'.format(self.network_interface))

        self._set_interface_mac_addr()
        self._set_network_address()

    def _check_monitor_mode(self):
        """
        Returns True if an interface is in monitor mode
        """
        result = False
        try:
            type_file = open('/sys/class/net/{0}/type'.format(self.network_interface), 'r')
            operdata_file = open('/sys/class/net/{0}/operstate'.format(self.network_interface), 'r')
        except:
            pass
        else:
            if type_file.read().startswith('80') and not operdata_file.read().startswith('down'):
                result = True
        return result

    def _set_interface_mac_addr(self):
        """
        Gets the MAC address of an interface
        """
        try:
            with open('/sys/class/net/{0}/address'.format(self.network_interface), 'r') as f:
                self.my_mac_address = f.read().strip()
        except FileNotFoundError:
            raise Exception('Interface {0} does not exist'.format(self.network_interface))
        except Exception:
            raise Exception('Unable to get MAC address for interface {0}'.format(self.network_interface))

    def _set_network_address(self):
        """
        Finds the corresponding normal interface for a monitor interface and
        then calculates the subnet address of this interface
        """
        for interface in os.listdir('/sys/class/net'):
            if interface in ['lo', self.network_interface]:
                continue
            try:
                with open('/sys/class/net/{0}/address'.format(interface), 'r') as f:
                    interface_mac_address = f.read().strip()
            except:
                pass
            else:
                if interface_mac_address == self.my_mac_address:
                    interface_details = ifaddresses(interface)
                    my_network = IPNetwork('{0}/{1}'.format(interface_details[2][0]['addr'], interface_details[2][0]['netmask']))
                    network_address = my_network.cidr
                    logger.debug('Calculated network {0} from interface {1}'.format(network_address, interface))
                    self.network_address = str(network_address)
        if not hasattr(self, 'network_address'):
            raise Exception('Unable to get network address for interface {0}'.format(self.network_interface))

    def telegram_send_message(self, message):
        if 'telegram_chat_ids' not in self.saved_data or self.saved_data['telegram_chat_ids'] is None:
            logger.error('Telegram failed to send message because Telegram chat_id is not set. Send a message to the Telegram bot')
            return False
        try:
            for chat_id in self.saved_data['telegram_chat_ids']:
                self.bot.sendMessage(chat_id=chat_id, parse_mode='Markdown', text=message, timeout=10)

        except Exception as e:
            logger.error('Telegram message failed to send message "{0}" with exception: {1}'.format(message, e))
        else:
            logger.info('Telegram message Sent: "{0}"'.format(message))
            return True

    def telegram_send_file(self, file_path):
        if 'telegram_chat_ids' not in self.saved_data:
            logger.error('Telegram failed to send file {0} because Telegram chat_id is not set. Send a message to the Telegram bot'.format(file_path))
            return False
        try:
            filename, file_extension = os.path.splitext(file_path)
            if file_extension == '.mp4':
                for chat_id in self.saved_data['telegram_chat_ids']:
                    self.bot.sendVideo(chat_id=chat_id, video=open(file_path, 'rb'), timeout=30)
            elif file_extension == '.gif':
                for chat_id in self.saved_data['telegram_chat_ids']:
                    self.bot.sendDocument(chat_id=chat_id, document=open(file_path, 'rb'), timeout=30)
            elif file_extension == '.jpeg':
                for chat_id in self.saved_data['telegram_chat_ids']:
                    self.bot.sendPhoto(chat_id=chat_id, photo=open(file_path, 'rb'), timeout=10)
            else:
                logger.error('Uknown file not sent: {0}'.format(file_path))
        except Exception as e:
            logger.error('Telegram failed to send file {0} with exception: {1}'.format(file_path, e))
            return False
        else:
            logger.info('Telegram file sent: {0}'.format(file_path))
            return True
