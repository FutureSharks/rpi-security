#!/usr/bin/python

import os, argparse

def parse_arguments():
    p = argparse.ArgumentParser(description='A simple security system for Raspberry Pi systems using a camera and PIR sensor.')
    p.add_argument('-c', '--config_file', help='Path to config file.', default='/etc/rpi-security.conf')
    p.add_argument('-d', '--debug', help='To enable debug output to stdout', action='store_true', default=False)
    return p.parse_args()

args = parse_arguments()

if not os.geteuid() == 0:
    sys.exit('%s must be run as root' % sys.argv[0])

import RPi.GPIO as GPIO
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
GPIO.setup(32, GPIO.OUT, initial=False)

from datetime import datetime
import syslog, sys, time, picamera, requests, csv, logging, signal, ast
requests.packages.urllib3.disable_warnings()
from pushbullet import Pushbullet
from ConfigParser import SafeConfigParser
from threading import Thread, current_thread
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff

def parse_configfile(config_file):
    config = SafeConfigParser()
    config.read(args.config_file)
    return dict(config.items('main'))

def get_network_address(interface_name):
    from netaddr import IPNetwork
    from netifaces import ifaddresses
    interface_details = ip = ifaddresses(interface_name)
    my_network = IPNetwork('%s/%s' % (ip[2][0]['addr'], ip[2][0]['netmask']))
    network_address = my_network.cidr
    log_message('Calculated network: %s' % network_address, 'debug')
    return network_address

def log_message(message, message_type = 'normal'):
    global debug_enabled
    if message_type == 'debug' and debug_enabled == False:
        return False
    elif debug_enabled == True:
        print datetime.now().strftime("%b %d %H:%M:%S"), 'rpi-security(%s): %s' % (current_thread().getName(), message)
    else:
        syslog.syslog(message)

def flash_camera_led(flash_time = 0.25):
        GPIO.output(32,True)
        time.sleep(flash_time)
        GPIO.output(32,False)

def take_photo(output_file):
    global debug_enabled
    time.sleep(2)
    if debug_enabled:
        flash_camera_led()
    camera.resolution = (2592, 1944)
    camera.capture(output_file)
    log_message("Captured image: %s" % output_file)

def archive_photo(photo_path):
    #command = 'cp %(source) %(destination)' % {"source": "/var/tmp/blah", "destination": "s3/blah/blah"}
    log_message(message='Archiving of photo complete: %s' % photo_path, message_type='debug')
    pass

def pb_send_notifcation(body, title):
    try:
        push = pushbullet.push_note(title, body)
    except requests.exceptions.RequestException as e:
        log_message(message='Pushbullet failed to get pushes with RequestException %s' % e)
    except Exception as e:
        pb_error = ast.literal_eval(e[0].encode('utf-8'))
        log_message(message='Pushbullet notification failed to send with error %s(%s): "%s, %s"' % (pb_error['error']['type'], pb_error['error']['message'], title, body))
    else:
        log_message(message='Pushbullet notification Sent: "%s, %s"' % (title, body))

def pb_send_file(file_path):
    with open(file_path, "rb") as pic:
        file_data = pushbullet.upload_file(pic, os.path.basename(file_path))
    try:
        push = pushbullet.push_file(**file_data)
    except requests.exceptions.RequestException as e:
        log_message(message='Pushbullet failed to send file %s  with RequestException %s' % (file_path, e))
        return False
    except Exception as e:
        pb_error = ast.literal_eval(e[0].encode('utf-8'))
        log_message(message='Pushbullet file failed to send with error %s(%s): %s' % (pb_error['error']['type'], pb_error['error']['message'], file_path))
        return False
    else:
        log_message('Pushbullet file sent: %s' % file_path)
        return True

def get_pushes():
    try:
        pushes = pushbullet.get_pushes()
    except requests.exceptions.RequestException as e:
        log_message(message='Pushbullet failed to get pushes with RequestException %s' % e)
    except Exception as e:
        pb_error = ast.literal_eval(e[0].encode('utf-8'))
        log_message(message='Pushbullet failed to get pushes with error %s(%s)' % (pb_error['error']['type'], pb_error['error']['message']))
    else:
        return pushes[1]

def pb_search_pushes(pushes, text):
    result = False
    for push in pushes:
        if 'body' in push and push['body'].lower() == text.lower():
            result = True
    return result

def process_photos():
    global captured_photos
    while True:
        if len(captured_photos) > 0:
            log_message(message='Starting to process photos', message_type='debug')
            for photo in list(captured_photos):
                log_message(message='Processing the photo: %s' % photo, message_type='debug')
                if pb_send_file(photo):
                    archive_photo(photo)
                    captured_photos.remove(photo)
        time.sleep(10)

def capture_packets(network_interface, mac_addresses):
    def update_time(packet):
        global alarm_state
        for mac_address in mac_addresses:
            if mac_address in packet[0].addr2 or mac_address in packet[0].addr3:
                alarm_state['last_packet_mac'] = mac_address
                break
        alarm_state['last_packet'] = time.time()
        log_message(message='Packet detected from %s' % str(alarm_state['last_packet_mac']), message_type='debug')
    def calculate_filter(mac_addresses):
        mac_string = ' or '.join(mac_addresses)
        return '(wlan addr2 (%(mac_string)s) or wlan addr3 (%(mac_string)s)) and type mgt subtype probe-req' % { 'mac_string' : mac_string }
    while True:
        sniff(iface=network_interface, store=0, prn=update_time, filter=calculate_filter(mac_addresses))

def monitor_alarm_state():
    global alarm_state
    last_pb_check = 0
    def send_status(alarm_state_dict):
        current_state = alarm_state_dict['current_state']
        previous_state = alarm_state_dict['previous_state']
        last_state_change = time.strftime("%D %H:%M", time.localtime(int(alarm_state_dict['last_state_change'])))
        last_packet = time.strftime("%D %H:%M", time.localtime(int(alarm_state_dict['last_packet'])))
        last_packet_mac = alarm_state_dict['last_packet_mac']
        return 'Current state is %s. Changed from %s at %s. The last MAC detect was %s at %s' % (current_state, previous_state, last_state_change, last_packet_mac, last_packet)
    def update_alarm_state(new_alarm_state):
        global alarm_state
        if new_alarm_state != alarm_state['current_state']:
            alarm_state['previous_state'] = alarm_state['current_state']
            alarm_state['current_state'] = new_alarm_state
            alarm_state['last_state_change'] = time.time()
            log_message("rpi-security is now %s" % alarm_state['current_state'])
            pb_send_notifcation(body = datetime.now().strftime("%b %d %H:%M:%S"), title = 'rpi-security: %s' % alarm_state['current_state'])
    while True:
        time.sleep(10)
        now = time.time()
        if now - last_pb_check > 300:
            pushes = get_pushes()
            last_pb_check = time.time()
            if pushes:
                if pb_search_pushes(pushes, 'disable'):
                    update_alarm_state('disabled')
                    continue
                elif 'body' in pushes[0] and pushes[0]['body'].lower() == 'status':
                    pb_send_notifcation(body = send_status(alarm_state), title = 'rpi-security')
                elif alarm_state['current_state'] == 'disabled':
                    update_alarm_state('disarmed')
        if alarm_state['current_state'] != 'disabled':
            if now - alarm_state['last_packet'] > 800:
                update_alarm_state('armed')
            else:
                update_alarm_state('disarmed')

def motion_detected(pir_pin):
    global alarm_state
    current_state = alarm_state['current_state']
    if current_state == 'armed':
        log_message('Motion detected')
        camera_output_file = config['image_path'] + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + ".jpg"
        take_photo(camera_output_file)
        captured_photos.append(camera_output_file)
    else:
        log_message('Motion detected but current_state is: %s' % current_state, message_type='debug')

def check_monitor_mode(network_interface):
    result = False
    try:
        f = open('/sys/class/net/%s/type' % network_interface, 'r')
    except:
        pass
    else:
        if f.read().startswith('80'):
            result = True
    return result

def exit(signal = None, frame = None):
    log_message("rpi-security stopping...")
    GPIO.cleanup()
    sys.exit(0)

def set_global_vars():
    global config
    config = parse_configfile(args.config_file)
    global debug_enabled
    debug_enabled = args.debug
    global camera
    camera = picamera.PiCamera()
    global pushbullet
    pushbullet = Pushbullet(config['pushbullet_access_token'])
    global pir_pin
    pir_pin = int(config['pir_pin'])
    global network_interface
    network_interface = config['network_interface']
    global mac_addresses
    if ',' in config['mac_addresses']:
        mac_addresses = config['mac_addresses'].split(',')
    else:
        mac_addresses = [ config['mac_addresses'] ]
    global alarm_state
    alarm_state = {
        'current_state': 'disarmed',
        'previous_state': 'not_running',
        'last_state_change': time.time(),
        'last_packet': time.time(),
        'last_packet_mac': None
    }
    global captured_photos
    captured_photos = []

if __name__ == "__main__":
    set_global_vars()
    if check_monitor_mode(network_interface) == False:
        sys.exit('Interface %s does not exist or is not in monitor mode.' % network_interface)
    monitor_alarm_state_thread = Thread(name='monitor_alarm_state', target=monitor_alarm_state)
    monitor_alarm_state_thread.daemon
    monitor_alarm_state_thread.start()
    capture_packets_thread = Thread(name='capture_packets', target=capture_packets, kwargs={'network_interface': network_interface, 'mac_addresses': mac_addresses})
    capture_packets_thread.daemon = True
    capture_packets_thread.start()
    process_photos_thread = Thread(name='process_photos', target=process_photos)
    process_photos_thread.daemon = True
    process_photos_thread.start()
    signal.signal(signal.SIGTERM, exit)
    time.sleep(2)
    try:
        log_message("rpi-security running")
        GPIO.setup(pir_pin, GPIO.IN)
        GPIO.add_event_detect(pir_pin, GPIO.RISING, callback=motion_detected)
        while 1:
            time.sleep(100)
    except KeyboardInterrupt:
        exit()
