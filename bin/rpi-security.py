#!/usr/bin/python

import os, argparse

def parse_arguments():
    p = argparse.ArgumentParser(description='A simple security system to run on a Raspberry Pi.')
    p.add_argument('-c', '--config_file', help='Path to config file.', default='/etc/rpi-security.conf')
    p.add_argument('-d', '--debug', help='To enable debug output to stdout', action='store_true', default=False)
    return p.parse_args()

args = parse_arguments()

if not os.geteuid() == 0:
    exit_with_error('%s must be run as root' % sys.argv[0])

import RPi.GPIO as GPIO
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
GPIO.setup(32, GPIO.OUT, initial=False)

from datetime import datetime
import syslog, sys, time, picamera, requests, csv, logging, signal, ast, telegram
requests.packages.urllib3.disable_warnings()
from ConfigParser import SafeConfigParser
from threading import Thread, current_thread
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import srp, Ether, ARP

start_time = time.time()

def parse_configfile(config_file):
    config = SafeConfigParser()
    config.read(config_file)
    return dict(config.items('main'))

def get_network_address(interface_name):
    """
    Calculates the network address of an interface. This is used in ARP scanning.
    """
    from netaddr import IPNetwork
    from netifaces import ifaddresses
    interface_details = ip = ifaddresses(interface_name)
    my_network = IPNetwork('%s/%s' % (ip[2][0]['addr'], ip[2][0]['netmask']))
    network_address = my_network.cidr
    log_message('Calculated network: %s' % network_address, message_type='debug')
    return str(network_address)

def log_message(message, message_type = 'normal'):
    if message_type == 'debug' and config['debug_enabled'] == False:
        return False
    elif config['debug_enabled'] == True:
        print datetime.now().strftime("%b %d %H:%M:%S"), 'rpi-security(%s): %s' % (current_thread().getName(), message)
    else:
        syslog.syslog(message)

def flash_camera_led(flash_time = 0.25):
        GPIO.output(32,True)
        time.sleep(flash_time)
        GPIO.output(32,False)

def take_photo():
    """
    Captures a photo and appends it to the captured_photos list for processessing.
    """
    camera_output_file = config['image_path'] + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + ".jpg"
    if config['debug_enabled']:
        flash_camera_led()
    config['camera'].capture(camera_output_file)
    log_message("Captured image: %s" % camera_output_file)
    captured_photos.append(camera_output_file)

def archive_photo(photo_path):
    #command = 'cp %(source) %(destination)' % {"source": "/var/tmp/blah", "destination": "s3/blah/blah"}
    log_message(message='Archiving of photo complete: %s' % photo_path, message_type='debug')
    pass

def telegram_send_message(message):
    try:
        chat_id = config['bot'].getUpdates()[-1].message.chat_id
        config['bot'].sendMessage(chat_id=chat_id, text=message)
    except Exception as e:
        log_message(message='Telegram message failed to send message "%s" with exception: %s' % (message, e))
    else:
        log_message(message='Telegram message Sent: "%s"' % message)

def telegram_send_photo(file_path):
    try:
        chat_id = config['bot'].getUpdates()[-1].message.chat_id
        config['bot'].sendPhoto(chat_id=chat_id, photo=open(file_path, 'rb'))
    except Exception as e:
        log_message(message='Telegram failed to send file %s with exception: %s' % (file_path, e))
    else:
        log_message('Telegram file sent: %s' % file_path)
        return True

def telegram_get_messages():
    """
    Returns list of Telegram messages.
    """
    try:
        updates = config['bot'].getUpdates()
    except Exception as e:
        log_message(message='Telegram failed to get updates with exception: %s' % e)
    else:
        return updates

def arp_ping_macs():
    """
    Performs an ARP scan of a destination MAC address to try and determine is it is alive.
    """
    def _arp_ping(mac_address, ip_address):
        result = False
        answered,unanswered = srp(Ether(dst=mac_address)/ARP(pdst=ip_address), timeout=1, verbose=False)
        if len(answered) > 0:
            for reply in answered:
                result = []
                result.append(str(reply[0].pdst))
                result = ', '.join(result)
        return result
    for mac_address in config['mac_addresses']:
        result = _arp_ping(mac_address, config['network_address'])
        if result:
            log_message('MAC %s responded to ARP ping with address %s' % (mac_address, result), message_type='debug')
            break
        else:
            log_message('MAC %s did not respond to ARP ping' % mac_address, message_type='debug')

def process_photos():
    """
    Monitors the captured_photos list for newly captured photos.
    When a new photos are present it will run arp_ping_macs to remove false positives and then send the photos via Telegram.
    After successfully sendind the photo it will also archive the photo and remove it from the list.
    """
    log_message("thread running")
    while True:
        if len(captured_photos) > 0:
            arp_ping_macs()
            time.sleep(1)
            arp_ping_macs()
            time.sleep(2)
            arp_ping_macs()
            time.sleep(3)
            now = time.time()
            if now - alarm_state['last_packet'] < 30:
                for photo in list(captured_photos):
                    log_message(message='Removing photo as it is a false positive: %s' % photo)
                    captured_photos.remove(photo)
            else:
                log_message(message='Starting to process photos', message_type='debug')
                alarm_state['alarm_triggered'] = True
                for photo in list(captured_photos):
                    log_message(message='Processing the photo: %s' % photo, message_type='debug')
                    if telegram_send_photo(photo):
                        archive_photo(photo)
                        captured_photos.remove(photo)
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
        log_message(message='Packet detected from %s' % str(alarm_state['last_packet_mac']), message_type='debug')
    def calculate_filter(mac_addresses):
        mac_string = ' or '.join(mac_addresses)
        return '((wlan addr2 (%(mac_string)s) or wlan addr3 (%(mac_string)s)) and type mgt subtype probe-req) or (wlan addr1 %(network_interface_mac)s and wlan addr3 (%(mac_string)s))' % { 'mac_string' : mac_string, 'network_interface_mac' : network_interface_mac }
    while True:
        log_message("thread running")
        sniff(iface=network_interface, store=0, prn=update_time, filter=calculate_filter(mac_addresses))

def monitor_alarm_state():
    """
    This function monitors and updates the alarm state based on data from Telegram and the alarm_state dictionary.
    """
    log_message("thread running")
    last_telegram_update = 0
    status_replied = {}
    def prepare_status(alarm_state_dict):
        current_state = alarm_state_dict['current_state']
        up_time = time.strftime("%H:%M:%S", time.gmtime(time.time() - start_time))
        previous_state = alarm_state_dict['previous_state']
        last_state_change = time.strftime("%D %H:%M", time.localtime(int(alarm_state_dict['last_state_change'])))
        last_packet = time.strftime("%D %H:%M", time.localtime(int(alarm_state_dict['last_packet'])))
        last_packet_mac = alarm_state_dict['last_packet_mac']
        alarm_triggered = alarm_state_dict['alarm_triggered']
        return 'Current state is %s. Uptime is %s. Changed from %s at %s. The last MAC detect was %s at %s. Alarm triggered: %s' % (current_state, up_time, previous_state, last_state_change, last_packet_mac, last_packet, alarm_triggered)
    def update_alarm_state(new_alarm_state):
        if new_alarm_state != alarm_state['current_state']:
            alarm_state['previous_state'] = alarm_state['current_state']
            alarm_state['current_state'] = new_alarm_state
            alarm_state['last_state_change'] = time.time()
            log_message("rpi-security is now %s" % alarm_state['current_state'])
            telegram_send_message('rpi-security: %s' % alarm_state['current_state'])
    while True:
        time.sleep(5)
        now = time.time()
        if now - last_telegram_update > 300:
            log_message('Checking Telegram for new messages', message_type='debug')
            last_telegram_update = time.time()
            messages = telegram_get_messages()
            if len(messages) < 1:
                log_message('No Telegram messages', message_type='debug')
            else:
                last_telegram_message = messages[-1]
                if 'disable' in last_telegram_message.message.text.lower():
                    update_alarm_state('disabled')
                if alarm_state['current_state'] == 'disabled' and 'enable' in last_telegram_message.message.text.lower():
                    update_alarm_state('disarmed')
                if 'status' in last_telegram_message.message.text.lower():
                    message_id = last_telegram_message.message.message_id
                    if message_id not in status_replied:
                        telegram_send_message('rpi-security status: %s' % prepare_status(alarm_state))
                        status_replied[message_id] = True
        if alarm_state['current_state'] != 'disabled':
            if now - alarm_state['last_packet'] > 720:
                update_alarm_state('armed')
            elif now - alarm_state['last_packet'] > 700:
                arp_ping_macs()
            else:
                update_alarm_state('disarmed')

def motion_detected(n):
    """
    Capture a photo if motion is detected and the alarm state is armed
    """
    current_state = alarm_state['current_state']
    if current_state == 'armed':
        log_message('Motion detected')
        take_photo()
        time.sleep(0.5)
        take_photo()
        time.sleep(0.5)
        take_photo()
        time.sleep(0.5)
        take_photo()
        time.sleep(0.5)
        take_photo()
        time.sleep(0.5)
    else:
        log_message('Motion detected but current_state is: %s' % current_state, message_type='debug')

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

def clean_exit(signal = None, frame = None):
    log_message("rpi-security stopping...")
    GPIO.cleanup()
    sys.exit(0)

def exit_with_error(message):
    log_message(message)
    GPIO.cleanup()
    sys.exit(1)

def set_global_vars():
    global config
    config = parse_configfile(args.config_file)
    config['debug_enabled'] = args.debug
    try:
        config['camera'] = picamera.PiCamera()
        config['camera'].resolution = (2592, 1944)
        config['camera'].vflip = True
        config['camera'].led = False
    except Exception as e:
        exit_with_error('Camera module failed to intialise with error %s' % e)
    try:
        config['bot'] = telegram.Bot(token=config['telegram_bot_token'])
    except Exception as e:
        exit_with_error('Failed to connect to Telegram with error: %s' % e)
    if ',' in config['mac_addresses']:
        config['mac_addresses'] = config['mac_addresses'].split(',')
    else:
        config['mac_addresses'] = [ config['mac_addresses'] ]
    global alarm_state
    alarm_state = {
        'current_state': 'disarmed',
        'previous_state': 'not_running',
        'last_state_change': time.time(),
        'last_packet': time.time(),
        'last_packet_mac': None,
        'alarm_triggered': False
    }
    global captured_photos
    captured_photos = []

if __name__ == "__main__":
    set_global_vars()
    if check_monitor_mode(config['network_interface']):
        config['network_interface_mac'] = get_interface_mac_addr(config['network_interface'])
        config['network_address'] = get_network_address('wlan0')
    else:
        exit_with_error('Interface %s does not exist, is not in monitor mode, is not up or MAC address unknown.' % config['network_interface'])
    monitor_alarm_state_thread = Thread(name='monitor_alarm_state', target=monitor_alarm_state)
    monitor_alarm_state_thread.daemon
    monitor_alarm_state_thread.start()
    capture_packets_thread = Thread(name='capture_packets', target=capture_packets, kwargs={'network_interface': config['network_interface'], 'network_interface_mac': config['network_interface_mac'], 'mac_addresses': config['mac_addresses']})
    capture_packets_thread.daemon = True
    capture_packets_thread.start()
    process_photos_thread = Thread(name='process_photos', target=process_photos)
    process_photos_thread.daemon = True
    process_photos_thread.start()
    signal.signal(signal.SIGTERM, exit)
    time.sleep(2)
    try:
        GPIO.setup(int(config['pir_pin']), GPIO.IN)
        GPIO.add_event_detect(int(config['pir_pin']), GPIO.RISING, callback=motion_detected)
        log_message("rpi-security running")
        telegram_send_message('rpi-security running')
        while 1:
            time.sleep(100)
    except KeyboardInterrupt:
        clean_exit()
