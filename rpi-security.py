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
import syslog, sys, os, argparse, time, picamera, requests, csv, logging, signal
requests.packages.urllib3.disable_warnings()
from pushbullet import Pushbullet
from ConfigParser import SafeConfigParser
from threading import Thread, current_thread
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import srp, sr, Ether, ARP, IP, ICMP
from random import shuffle

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

def log_message(message, source = 'main', message_type = 'normal'):
    global debug_enabled
    if message_type == 'debug' and debug_enabled == False:
        return False
    elif debug_enabled == True:
        print datetime.now().strftime("%b %d %H:%M:%S"), 'rpi-security(%s): %s' % (source, message)
    else:
        syslog.syslog(message)

def flash_camera_led(flash_time = 0.25):
        GPIO.output(32,True)
        time.sleep(flash_time)
        GPIO.output(32,False)

def take_photo(output_file):
    global debug_enabled
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
    except Exception as e:
        log_message(message='Pushbullet notification failed to send (error %s): "%s, %s"' % (e, title, body))
    else:
        log_message(message='Pushbullet notification Sent: "%s, %s"' % (title, body))

def pb_send_file(file_path):
    with open(file_path, "rb") as pic:
        file_data = pushbullet.upload_file(pic, os.path.basename(file_path))
    try:
        push = pushbullet.push_file(**file_data)
    except Exception as e:
        log_message(message='Pushbullet file failed to send (error %s): %s' % (e, file_path))
    else:
        log_message('Pushbullet file sent: %s' % file_path)

def pb_search_pushes(text):
    result = False
    try:
        pushes = pushbullet.get_pushes()
    except Exception as e:
        log_message(message='Pushbullet failed to get pushes with error %s' % e)
    else:
        for push in pushes[1]:
            if 'body' in push and push['body'].lower() == text.lower():
                result = True
        return result

def process_photos():
    global captured_photos
    while True:
        if len(captured_photos) > 0:
            log_message(message='Starting to process photos', source=current_thread().getName(), message_type='debug')
            for photo in list(captured_photos):
                log_message(message='Processing the photo: %s' % photo, source=current_thread().getName(), message_type='debug')
                pb_send_file(photo)
                archive_photo(photo)
                captured_photos.remove(photo)
        time.sleep(10)

def scan_network(scan_interval, mac_addresses, network_address):
    global alarm_state
    arp_cache = {}
    logging_source = current_thread().getName()
    def ping_ip(ip_address):
        result = False
        answered,unanswered=sr(IP(dst=ip_address)/ICMP(), retry=0, timeout=0.25, verbose=False)
        if len(answered) > 0:
            result = True
        return result
    def arp_ping(mac_address, ip_address):
        result = False
        answered,unanswered = srp(Ether(dst=mac_address)/ARP(pdst=ip_address), timeout=1, verbose=False)
        if len(answered) > 0:
            for reply in answered:
                result = []
                result.append(str(reply[0].pdst))
        return result
    def print_from_arp_cache(arp_cache):
        result = False
        for mac, ip_address in arp_cache.iteritems():
            if ping_ip(ip_address):
                log_message(message='Ping of %s from arp_cache entry for %s successful.' % (ip_address, mac), source=logging_source, message_type='debug')
                result = True
                break
            else:
                log_message(message='Ping of %s from arp_cache entry for %s unsuccessful.' % (ip_address, mac), source=logging_source, message_type='debug')
        return result

    while True:
        if pb_search_pushes('disable') == True:
            alarm_state = 'disabled'
        else:
            log_message(message='Starting network scan, interval is %s' % scan_interval, source=logging_source, message_type='debug')
            if print_from_arp_cache(arp_cache):
                new_alarm_state = 'disarmed'
            else:
                shuffle(mac_addresses)
                for mac_address in mac_addresses:
                    log_message(message='Trying to detect MAC: %s' % mac_address, source=logging_source, message_type='debug')
                    arp_ping_result = arp_ping(str(mac_address), str(network_address))
                    if arp_ping_result and len(arp_ping_result) == 1:
                        arp_cache[mac_address] = arp_ping_result[0]
                        new_alarm_state = 'disarmed'
                        log_message(message='ARP ping of MAC addres %s successful' % mac_address, source=logging_source, message_type='debug')
                        break
                    elif arp_ping_result and len(arp_ping_result) > 1:
                        new_alarm_state = 'disarmed'
                        log_message(message='MAC address %s is ARP pingable but more than one host replied: %s' % (mac_address, arp_ping_result), source=logging_source)
                    else:
                        log_message(message='ARP ping of MAC addres %s unsuccessful' % mac_address, source=logging_source, message_type='debug')
                        new_alarm_state = 'armed'
            if new_alarm_state != alarm_state:
                alarm_state = new_alarm_state
                log_message("rpi-security is now %s" % alarm_state, source=logging_source)
                pb_send_notifcation(body = datetime.now().strftime("%b %d %H:%M:%S"), title = 'rpi-security: %s' % alarm_state)
        time.sleep(scan_interval)

def motion_detected(pir_pin):
    global alarm_state
    if alarm_state == 'armed':
        log_message('Motion detected')
        camera_output_file = config['image_path'] + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + ".jpg"
        take_photo(camera_output_file)
        captured_photos.append(camera_output_file)
    else:
        log_message('Motion detected but alarm_state is: %s' % alarm_state, source='motion_detected', message_type='debug')

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
    global scan_interval
    scan_interval = int(config['scan_interval'])
    global mac_addresses
    mac_addresses = config['mac_addresses'].split(',')
    global alarm_state
    alarm_state = 'initial'
    global captured_photos
    captured_photos = []

if __name__ == "__main__":
    set_global_vars()
    scan_network_thread = Thread(name='scan_network', target=scan_network, kwargs={'scan_interval': scan_interval, 'mac_addresses': mac_addresses, 'network_address': get_network_address(config['network_interface'])})
    scan_network_thread.daemon = True
    scan_network_thread.start()
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
