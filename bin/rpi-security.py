#!/usr/bin/python

import os
import argparse
import logging
import logging.handlers
from ConfigParser import SafeConfigParser
import RPi.GPIO as GPIO
from datetime import datetime, timedelta
import sys
import time
import signal
import yaml

def parse_arguments():
    p = argparse.ArgumentParser(description='A simple security system to run on a Raspberry Pi.')
    p.add_argument('-c', '--config_file', help='Path to config file.', default='/etc/rpi-security.conf')
    p.add_argument('-s', '--state_file', help='Path to state file.', default='/var/lib/rpi-security/state.yaml')
    p.add_argument('-d', '--debug', help='To enable debug output to stdout', action='store_true', default=False)
    return p.parse_args()

def check_monitor_mode(network_interface):
    """
    Returns True if an interface is in monitor mode
    """
    result = False
    try:
        type_file = open('/sys/class/net/%s/type' % network_interface, 'r')
        operstate_file = open('/sys/class/net/%s/operstate' % network_interface, 'r')
    except:
        pass
    else:
        if type_file.read().startswith('80') and not operstate_file.read().startswith('down'):
            result = True
    return result

def get_network_address(interface_name):
    """
    Calculates the network address of an interface. This is used in ARP scanning.
    """
    from netaddr import IPNetwork
    from netifaces import ifaddresses
    interface_details = ifaddresses(interface_name)
    my_network = IPNetwork('%s/%s' % (interface_details[2][0]['addr'], interface_details[2][0]['netmask']))
    network_address = my_network.cidr
    logger.debug('Calculated network: %s' % network_address)
    return str(network_address)

def get_interface_mac_addr(network_interface):
    """
    Returns the MAC address of an interface
    """
    result = False
    try:
        f = open('/sys/class/net/%s/address' % network_interface, 'r')
    except:
        pass
    else:
        result = f.read().strip()
    return result

def parse_config_file(config_file):
    def str2bool(v):
        return v.lower() in ("yes", "true", "t", "1")
    default_config = {
        'camera_save_path': '/var/tmp',
        'network_interface': 'mon0',
        'packet_timeout': '700',
        'debug_mode': 'False',
        'pir_pin': '14',
        'camera_vflip': 'False',
        'camera_hflip': 'False',
        'camera_image_size': '1024x768',
        'camera_mode': 'video',
        'camera_capture_length': '3'
    }
    cfg = SafeConfigParser(defaults=default_config)
    cfg.read(config_file)
    dict_config = dict(cfg.items('main'))
    dict_config['debug_mode'] = str2bool(dict_config['debug_mode'])
    dict_config['camera_vflip'] = str2bool(dict_config['camera_vflip'])
    dict_config['camera_hflip'] = str2bool(dict_config['camera_hflip'])
    dict_config['pir_pin'] = int(dict_config['pir_pin'])
    dict_config['camera_image_size'] = tuple([int(x) for x in dict_config['camera_image_size'].split('x')])
    dict_config['camera_capture_length'] = int(dict_config['camera_capture_length'])
    dict_config['packet_timeout'] = int(dict_config['packet_timeout'])
    if ',' in dict_config['mac_addresses']:
        dict_config['mac_addresses'] = dict_config['mac_addresses'].lower().split(',')
    else:
        dict_config['mac_addresses'] = [ dict_config['mac_addresses'].lower() ]
    return dict_config

def read_state_file(state_file):
    result = {}
    try:
        with open(state_file, 'r') as stream:
            result = yaml.load(stream) or {}
    except Exception as e:
        logger.error('Failed to read state file %s: %s' % (state_file, e))
    else:
        logger.debug('State file read: %s' % state_file)
    return result

def write_state_file(state_file, state_data):
    """
    Writes a state file to disk.
    """
    try:
        with open(state_file, 'w') as f:
            yaml.dump(state_data, f, default_flow_style=False)
    except Exception as e:
        logger.error('Failed to write state file %s: %s' % (state_file, e))
    else:
        logger.debug('State file written: %s' % state_file)

def take_photo(output_file):
    """
    Captures a photo and saves it disk.
    """
    if args.debug:
        GPIO.output(32, True)
        time.sleep(0.25)
        GPIO.output(32, False)
    try:
        camera.capture(output_file)
    except Exception as e:
        logger.error('Failed to take photo: %s' % e)
        return False
    else:
        logger.info("Captured image: %s" % output_file)
        return True

def take_gif(output_file, length):
    temp_jpeg_path = config['camera_save_path'] + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + 'gif-part'
    jpeg_files = ['%s-%s.jpg' % (temp_jpeg_path, i) for i in range(length*3)]
    try:
        for jpeg in jpeg_files:
            camera.capture(jpeg, resize=(800,600))
        im=Image.open(jpeg_files[0])
        jpeg_files_no_first_frame=[x for x in jpeg_files if x != jpeg_files[0]]
        ims = [Image.open(i) for i in jpeg_files_no_first_frame]
        im.save(output_file, append_images=ims, save_all=True, loop=0, duration=200)
        im.close()
        for imfile in ims:
            imfile.close()
        for jpeg in jpeg_files:
            os.remove(jpeg)
    except Exception as e:
        logger.error('Failed to create GIF: %s' % e)
        return False
    else:
        logger.info("Captured gif: %s" % output_file)
        return True

def archive_photo(photo_path):
    #command = 'cp %(source) %(destination)' % {"source": "/var/tmp/blah", "destination": "s3/blah/blah"}
    logger.debug('Archiving of photo complete: %s' % photo_path)
    pass

def telegram_send_message(message):
    if 'telegram_chat_id' not in state:
        logger.error('Telegram failed to send message because Telegram chat_id is not set. Send a message to the Telegram bot')
        return False
    try:
        bot.sendMessage(chat_id=state['telegram_chat_id'], parse_mode='Markdown', text=message, timeout=10)
    except Exception as e:
        logger.error('Telegram message failed to send message "%s" with exception: %s' % (message, e))
    else:
        logger.info('Telegram message Sent: "%s"' % message)
        return True

def telegram_send_file(file_path):
    if 'telegram_chat_id' not in state:
        logger.error('Telegram failed to send file %s because Telegram chat_id is not set. Send a message to the Telegram bot' % file_path)
        return False
    filename, file_extension = os.path.splitext(file_path)
    try:
        if file_extension == '.mp4':
            bot.sendVideo(chat_id=state['telegram_chat_id'], video=open(file_path, 'rb'), timeout=30)
        elif file_extension == '.gif':
            bot.sendDocument(chat_id=state['telegram_chat_id'], document=open(file_path, 'rb'), timeout=30)
        elif file_extension == '.jpeg':
            bot.sendPhoto(chat_id=state['telegram_chat_id'], photo=open(file_path, 'rb'), timeout=10)
        else:
            logger.error('Uknown file not sent: %s' % file_path)
    except Exception as e:
        logger.error('Telegram failed to send file %s with exception: %s' % (file_path, e))
        return False
    else:
        logger.info('Telegram file sent: %s' % file_path)
        return True

def arp_ping_macs(mac_addresses, repeat=1):
    """
    Performs an ARP scan of a destination MAC address to try and determine if they are present on the network.
    """
    def _arp_ping(mac_address, ip_address):
        result = False
        answered,unanswered = srp(Ether(dst=mac_address)/ARP(pdst=ip_address), timeout=1, verbose=False)
        if len(answered) > 0:
            for reply in answered:
                if reply[1].hwsrc == mac_address:
                    if type(result) is not list:
                        result = []
                    result.append(str(reply[1].psrc))
                    result = ', '.join(result)
        return result
    while repeat > 0:
        if time.time() - alarm_state['last_packet'] < 30:
            break
        for mac_address in mac_addresses:
            result = _arp_ping(mac_address, config['network_address'])
            if result:
                logger.debug('MAC %s responded to ARP ping with address %s' % (mac_address, result))
                break
            else:
                logger.debug('MAC %s did not respond to ARP ping' % mac_address)
        if repeat > 1:
            time.sleep(2)
        repeat -= 1

def process_photos():
    """
    Monitors the captured_from_camera list for newly captured photos.
    When a new photos are present it will run arp_ping_macs to remove false positives and then send the photos via Telegram.
    After successfully sendind the photo it will also archive the photo and remove it from the list.
    """
    logger.info("thread running")
    while True:
        if len(captured_from_camera) > 0:
            if alarm_state['current_state'] == 'armed':
                arp_ping_macs(mac_addresses=config['mac_addresses'], repeat=3)
                for photo in list(captured_from_camera):
                    if alarm_state['current_state'] != 'armed':
                        break
                    logger.debug('Processing the photo: %s' % photo)
                    alarm_state['alarm_triggered'] = True
                    if telegram_send_file(photo):
                        archive_photo(photo)
                        captured_from_camera.remove(photo)
            else:
                logger.debug('Stopping photo processing as state is now %s' % alarm_state['current_state'])
                for photo in list(captured_from_camera):
                    logger.info('Removing photo as it is a false positive: %s' % photo)
                    captured_from_camera.remove(photo)
                    # Delete the photo file
        time.sleep(5)

def capture_packets(network_interface, network_interface_mac, mac_addresses):
    """
    This function uses scapy to sniff packets for our MAC addresses and updates a counter when packets are detected.
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import sniff
    def update_time(packet):
        for mac_address in mac_addresses:
            if mac_address in packet[0].addr2 or mac_address in packet[0].addr3:
                alarm_state['last_packet_mac'] = mac_address
                break
        alarm_state['last_packet'] = time.time()
        logger.debug('Packet detected from %s' % str(alarm_state['last_packet_mac']))
    def calculate_filter(mac_addresses):
        mac_string = ' or '.join(mac_addresses)
        return '((wlan addr2 (%(mac_string)s) or wlan addr3 (%(mac_string)s)) and type mgt subtype probe-req) or (wlan addr1 %(network_interface_mac)s and wlan addr3 (%(mac_string)s))' % { 'mac_string' : mac_string, 'network_interface_mac' : network_interface_mac }
    while True:
        logger.info("thread running")
        try:
            sniff(iface=network_interface, store=0, prn=update_time, filter=calculate_filter(mac_addresses))
        except Exception as e:
            exit_error('Scapy failed to sniff with error %s. Please check help or update scapy version' % e)

def update_alarm_state(new_alarm_state):
    if new_alarm_state != alarm_state['current_state']:
        alarm_state['previous_state'] = alarm_state['current_state']
        alarm_state['current_state'] = new_alarm_state
        alarm_state['last_state_change'] = time.time()
        logger.info("rpi-security is now %s" % alarm_state['current_state'])
        telegram_send_message('rpi-security: *%s*' % alarm_state['current_state'])

def monitor_alarm_state():
    """
    This function monitors and updates the alarm state based on data from Telegram and the alarm_state dictionary.
    """
    logger.info("thread running")
    while True:
        time.sleep(3)
        now = time.time()
        if alarm_state['current_state'] != 'disabled':
            if now - alarm_state['last_packet'] > config['packet_timeout'] + 20:
                update_alarm_state('armed')
            elif now - alarm_state['last_packet'] > config['packet_timeout']:
                arp_ping_macs(config['mac_addresses'])
            else:
                update_alarm_state('disarmed')

def telegram_bot(token):
    """
    This function runs the telegram bot that responds to commands like /enable, /disable or /status.
    """
    def prepare_status(alarm_state_dict):
        def readable_delta(then, now=time.time()):
            td = timedelta(seconds=now - then)
            days, hours, minutes = td.days, td.seconds // 3600, td.seconds // 60 % 60
            text = '%s minutes' % minutes
            if hours > 0:
                text = '%s hours and ' % hours + text
                if days > 0:
                    text = '%s days, ' % days + text
            return text
        return '*rpi-security status*\nCurrent state: _%s_\nLast state: _%s_\nLast change: _%s ago_\nUptime: _%s_\nLast MAC detected: _%s %s ago_\nAlarm triggered: _%s_' % (
                alarm_state_dict['current_state'],
                alarm_state_dict['previous_state'],
                readable_delta(alarm_state_dict['last_state_change']),
                readable_delta(alarm_state_dict['start_time']),
                alarm_state_dict['last_packet_mac'],
                readable_delta(alarm_state_dict['last_packet']),
                alarm_state_dict['alarm_triggered']
            )
    def save_chat_id(bot, update):
        if 'telegram_chat_id' not in state:
            state['telegram_chat_id'] = update.message.chat_id
            write_state_file(state_file=args.state_file, state_data=state)
            logger.debug('Set Telegram chat_id %s' % update.message.chat_id)
    def debug(bot, update):
        logger.debug('Received Telegram bot message: %s' % update.message.text)
    def check_chat_id(update):
        if update.message.chat_id != state['telegram_chat_id']:
            logger.debug('Ignoring Telegam update with filtered chat id %s: %s' % (update.message.chat_id, update.message.text))
            return False
        else:
            return True
    def help(bot, update):
        if check_chat_id(update):
            bot.sendMessage(update.message.chat_id, parse_mode='Markdown', text='/status: Request status\n/disable: Disable alarm\n/enable: Enable alarm\n/photo: Take a photo\n/gif: Take a gif\n', timeout=10)
    def status(bot, update):
        if check_chat_id(update):
            bot.sendMessage(update.message.chat_id, parse_mode='Markdown', text=prepare_status(alarm_state), timeout=10)
    def disable(bot, update):
        if check_chat_id(update):
            update_alarm_state('disabled')
    def enable(bot, update):
        if check_chat_id(update):
            update_alarm_state('disarmed')
    def photo(bot, update):
        if check_chat_id(update):
            file_path = config['camera_save_path'] + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + '.jpeg'
            take_photo(file_path)
            telegram_send_file(file_path)
    def gif(bot, update):
        if check_chat_id(update):
            file_path = config['camera_save_path'] + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + '.gif'
            take_gif(file_path, config['camera_capture_length'])
            telegram_send_file(file_path)
    def error(bot, update, error):
        logger.error('Update "%s" caused error "%s"' % (update, error))
    updater = Updater(token)
    dp = updater.dispatcher
    dp.add_handler(RegexHandler('.*', save_chat_id), group=1)
    dp.add_handler(RegexHandler('.*', debug), group=2)
    dp.add_handler(CommandHandler("help", help))
    dp.add_handler(CommandHandler("status", status))
    dp.add_handler(CommandHandler("disable", disable))
    dp.add_handler(CommandHandler("enable", enable))
    dp.add_handler(CommandHandler("photo", photo))
    dp.add_handler(CommandHandler("gif", gif))
    dp.add_error_handler(error)
    logger.info("thread running")
    updater.start_polling(timeout=10)

def motion_detected(channel):
    """
    Capture a photo if motion is detected and the alarm state is armed
    """
    current_state = alarm_state['current_state']
    if current_state == 'armed':
        logger.info('Motion detected')
        file_prefix = config['camera_save_path'] + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S")
        if config['camera_mode'].lower() == 'gif':
            camera_output_file = "%s.gif" % file_prefix
            take_gif(camera_output_file, config['camera_capture_length'])
            captured_from_camera.append(camera_output_file)
        elif config['camera_mode'].lower() == 'photo':
            for i in range(0, config['camera_capture_length'], 1):
                camera_output_file = "%s-%s.jpeg" % (file_prefix, i)
                take_photo(camera_output_file)
                captured_from_camera.append(camera_output_file)
        else:
            logger.error("Unkown camera_mode %s" % config['camera_mode'])
    else:
        logger.debug('Motion detected but current_state is: %s' % current_state)

def exit_cleanup():
    GPIO.cleanup()
    if 'camera' in vars():
        camera.close()

def exit_clean(signal=None, frame=None):
    logger.info("rpi-security stopping...")
    exit_cleanup()
    sys.exit(0)

def exit_error(message):
    logger.critical(message)
    exit_cleanup()
    try:
        current_thread().getName()
    except NameError:
        sys.exit(1)
    else:
        os._exit(1)

def exception_handler(type, value, tb):
    logger.exception("Uncaught exception: {0}" % format(str(value)))

def setup_logging(debug_mode=False, log_to_stdout=False):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    syslog_handler = logging.handlers.SysLogHandler(address = '/dev/log')
    syslog_format = logging.Formatter("%(filename)s:%(threadName)s %(message)s", "%Y-%m-%d %H:%M:%S")
    syslog_handler.setFormatter(syslog_format)
    if log_to_stdout:
        stdout_level = logging.DEBUG
        stdout_format = logging.Formatter("%(asctime)s %(levelname)-7s %(filename)s:%(lineno)-3s %(threadName)-19s %(message)s", "%Y-%m-%d %H:%M:%S")
    else:
        stdout_level = logging.CRITICAL
        stdout_format = logging.Formatter("ERROR: %(message)s")
    if debug_mode:
        syslog_handler.setLevel(logging.DEBUG)
    else:
        syslog_handler.setLevel(logging.INFO)
    logger.addHandler(syslog_handler)
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(stdout_format)
    stdout_handler.setLevel(stdout_level)
    logger.addHandler(stdout_handler)
    return logger

if __name__ == "__main__":
    GPIO.setwarnings(False)
    # Parse arguments and configuration, set up logging
    args = parse_arguments()
    config = parse_config_file(args.config_file)
    logger = setup_logging(debug_mode=config['debug_mode'], log_to_stdout=args.debug)
    state = read_state_file(args.state_file)
    sys.excepthook = exception_handler
    captured_from_camera = []
    # Some intial checks before proceeding
    if check_monitor_mode(config['network_interface']):
        config['network_interface_mac'] = get_interface_mac_addr(config['network_interface'])
        # Hard coded interface name here. Need a better solution...
        config['network_address'] = get_network_address('wlan0')
    else:
        exit_error('Interface %s does not exist, is not in monitor mode, is not up or MAC address unknown.' % config['network_interface'])
    if not os.geteuid() == 0:
        exit_error('%s must be run as root' % sys.argv[0])
    # Now begin importing slow modules and setting up camera, Telegram and threads
    import picamera
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import srp, Ether, ARP
    from scapy.all import conf as scapy_conf
    scapy_conf.promisc=0
    scapy_conf.sniff_promisc=0
    import telegram
    from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, RegexHandler
    from threading import Thread, current_thread
    from PIL import Image
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(32, GPIO.OUT, initial=False)
    try:
        camera = picamera.PiCamera()
        camera.resolution = config['camera_image_size']
        camera.vflip = config['camera_vflip']
        camera.led = False
    except Exception as e:
        exit_error('Camera module failed to intialise with error %s' % e)
    try:
        bot = telegram.Bot(token=config['telegram_bot_token'])
    except Exception as e:
        exit_error('Failed to connect to Telegram with error: %s' % e)
    # Set the initial alarm_state dictionary
    alarm_state = {
        'start_time': time.time(),
        'current_state': 'disarmed',
        'previous_state': 'stopped',
        'last_state_change': time.time(),
        'last_packet': time.time(),
        'last_packet_mac': None,
        'alarm_triggered': False
    }
    # Start the threads
    telegram_bot_thread = Thread(name='telegram_bot', target=telegram_bot, kwargs={'token': config['telegram_bot_token']})
    telegram_bot_thread.daemon = True
    telegram_bot_thread.start()
    monitor_alarm_state_thread = Thread(name='monitor_alarm_state', target=monitor_alarm_state)
    monitor_alarm_state_thread.daemon = True
    monitor_alarm_state_thread.start()
    capture_packets_thread = Thread(name='capture_packets', target=capture_packets, kwargs={'network_interface': config['network_interface'], 'network_interface_mac': config['network_interface_mac'], 'mac_addresses': config['mac_addresses']})
    capture_packets_thread.daemon = True
    capture_packets_thread.start()
    process_photos_thread = Thread(name='process_photos', target=process_photos)
    process_photos_thread.daemon = True
    process_photos_thread.start()
    signal.signal(signal.SIGTERM, exit_clean)
    time.sleep(2)
    try:
        GPIO.setup(config['pir_pin'], GPIO.IN)
        GPIO.add_event_detect(config['pir_pin'], GPIO.RISING, callback=motion_detected)
        logger.info("rpi-security running")
        telegram_send_message('rpi-security running')
        while 1:
            time.sleep(100)
    except KeyboardInterrupt:
        exit_clean()
