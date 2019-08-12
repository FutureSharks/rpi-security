#!/usr/bin/env python3

import argparse
import logging
import logging.handlers
import sys
import signal
import time
import rpisec
from threading import Thread


def parse_arguments():
    p = argparse.ArgumentParser(description='A simple security system to run on a Raspberry Pi.')
    p.add_argument('-c', '--config_file', help='Path to config file.', default='/etc/rpi-security.conf')
    p.add_argument('-s', '--data_file', help='Path to data file.', default='/var/lib/rpi-security/data.yaml')
    p.add_argument('-d', '--debug', help='To enable debug output to stdout', action='store_true', default=False)
    return p.parse_args()

def setup_logging(debug_mode, log_to_stdout):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    syslog_handler = logging.handlers.SysLogHandler(address = '/dev/log')
    syslog_format = logging.Formatter("rpi-security %(threadName)s %(message)s", "%Y-%m-%d %H:%M:%S")
    syslog_handler.setFormatter(syslog_format)
    if log_to_stdout:
        stdout_level = logging.DEBUG
        stdout_format = logging.Formatter("%(asctime)s %(levelname)-7s %(filename)s:%(lineno)-12s %(threadName)-25s %(message)s", "%Y-%m-%d %H:%M:%S")
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
    args = parse_arguments()
    logger = setup_logging(debug_mode=False, log_to_stdout=args.debug)

    try:
        rpis = rpisec.RpisSecurity(args.config_file, args.data_file)
        camera = rpisec.RpisCamera(photo_size=rpis.photo_size, gif_size=rpis.gif_size,
            motion_size=rpis.motion_size, motion_detection_threshold=rpis.motion_detection_threshold,
            camera_vflip=rpis.camera_vflip, camera_hflip=rpis.camera_hflip,
            camera_capture_length=rpis.camera_capture_length,camera_mode=rpis.camera_mode
        )
        if rpis.debug_mode:
            logger.handlers[0].setLevel(logging.DEBUG)
    except Exception as e:
        rpisec.exit_error('Configuration error: {0}'.format(repr(e)))

    sys.excepthook = rpisec.exception_handler

    # Start the threads
    telegram_bot_thread = Thread(name='telegram_bot', target=rpisec.threads.telegram_bot, args=(rpis, camera))
    telegram_bot_thread.daemon = True
    telegram_bot_thread.start()
    monitor_alarm_state_thread = Thread(name='monitor_alarm_state', target=rpisec.threads.monitor_alarm_state, args=(rpis, camera))
    monitor_alarm_state_thread.daemon = True
    monitor_alarm_state_thread.start()
    capture_packets_thread = Thread(name='capture_packets', target=rpisec.threads.capture_packets, args=(rpis,))
    capture_packets_thread.daemon = True
    capture_packets_thread.start()
    process_photos_thread = Thread(name='process_photos', target=rpisec.threads.process_photos, args=(rpis, camera))
    process_photos_thread.daemon = True
    process_photos_thread.start()
    signal.signal(signal.SIGTERM, rpisec.exit_clean)
    try:
        logger.info("rpi-security running")
        rpis.telegram_send_message('rpi-security running')
        while True:
            time.sleep(100)
    except KeyboardInterrupt:
        rpisec.exit_clean()
