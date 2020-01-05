# -*- coding: utf-8 -*-

import logging
import os
import time
import io
import imutils
import time
import cv2
from picamera.array import PiMotionAnalysis
from picamera import PiCamera
from picamera import PiCameraRuntimeError
import numpy as np
from PIL import Image
from threading import Lock, Event
from queue import Queue
from .exit_clean import exit_error
from datetime import datetime
from fractions import Fraction


logger = logging.getLogger()


class RpisCamera(object):
    '''
    A wrapper for the camera. Runs motion detection, provides a queue for photos,
    captues photos and GIFs.
    '''
    def __init__(self, photo_size, gif_size, motion_size, camera_vflip,
            camera_hflip, camera_capture_length, motion_detection_threshold,
            camera_mode):
        self.photo_size = photo_size
        self.gif_size = gif_size
        self.camera_vflip = camera_vflip
        self.camera_hflip = camera_hflip
        self.lock = Lock()
        self.queue = Queue()
        self.motion_framerate = 5
        self.motion_size = motion_size
        self.motion_detection_threshold = motion_detection_threshold
        self.temp_directory = '/var/tmp'
        self.camera_save_path = '/var/tmp'
        self.camera_capture_length = camera_capture_length
        self.camera_mode = camera_mode
        self.motion_detection_running = False
        self.too_dark_message_printed = False

        try:
            self.camera = PiCamera()
            self.camera.vflip = self.camera_vflip
            self.camera.hflip = self.camera_hflip
        except Exception as e:
            exit_error('Camera module failed to intialise with error {0}'.format(repr(e)))

    def take_photo(self, filename_extra_suffix=''):
        """
        Captures a photo and saves it disk.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        photo = '{0}/rpi-security-{1}{2}.jpeg'.format(self.camera_save_path, timestamp, filename_extra_suffix)
        try:
            with self.lock:
                while self.camera.recording:
                    time.sleep(0.1)
                time.sleep(1)
                self.camera.resolution = self.photo_size
                self.camera.capture(photo, use_video_port=False)
        except PiCameraRuntimeError as e:
            logger.error('Failed to take photo, camera error: {0}'.format(repr(e)))
            return None
        except Exception as e:
            logger.error('Failed to take photo: {0}'.format(repr(e)))
            return None
        else:
            logger.info("Captured image: {0}".format(photo))
            return photo

    def take_gif(self):
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        gif = '{0}/rpi-security-{1}.gif'.format(self.camera_save_path, timestamp)
        temp_jpeg_path = '{0}/rpi-security-{1}-gif-part'.format(self.temp_directory, timestamp)
        jpeg_files = ['{0}-{1}.jpg'.format(temp_jpeg_path, i) for i in range(self.camera_capture_length*3)]
        try:
            for jpeg in jpeg_files:
                with self.lock:
                    while self.camera.recording:
                        time.sleep(0.1)
                    time.sleep(1)
                    self.camera.resolution = self.gif_size
                    self.camera.capture(jpeg)
            im=Image.open(jpeg_files[0])
            jpeg_files_no_first_frame=[x for x in jpeg_files if x != jpeg_files[0]]
            ims = [Image.open(i) for i in jpeg_files_no_first_frame]
            im.save(gif, append_images=ims, save_all=True, loop=0, duration=200)
            for jpeg in jpeg_files:
                os.remove(jpeg)
        except Exception as e:
            logger.error('Failed to create GIF: {0}'.format(repr(e)))
            return None
        else:
            logger.info("Captured gif: {0}".format(gif))
            return gif

    def trigger_camera(self):
        if self.camera_mode == 'gif':
            captured = self.take_gif()
            self.queue.put(captured)
        elif self.camera_mode == 'photo':
            for i in range(0, self.camera_capture_length, 1):
                captured = self.take_photo(filename_extra_suffix='-{0}'.format(i))
                self.queue.put(captured)
        else:
            logger.error('Unsupported camera_mode: {0}'.format(self.camera_mode))

    def start_motion_detection(self, rpis):
        past_frame = None
        while not self.lock.locked() and rpis.state.current == 'armed':
            if not self.motion_detection_running:
                logger.debug("Starting motion detection")
                self.motion_detection_running = True
            stream = io.BytesIO()
            self.camera.resolution = self.motion_size
            self.camera.capture(stream, format='jpeg', use_video_port=False)
            data = np.fromstring(stream.getvalue(), dtype=np.uint8)
            frame = cv2.imdecode(data, 1)

            # if frame is initialized, we have not reach the end of the video
            if frame is not None:
                past_frame = self.handle_new_frame(frame, past_frame)
            else:
                logger.error("No more frame")
            rpis.state.check()
            time.sleep(0.2)
        else:
            self.stop_motion_detection()

    def handle_new_frame(self, frame, past_frame):
        (h, w) = frame.shape[:2]
        r = 500 / float(w)
        dim = (500, int(h * r))
        frame = cv2.resize(frame, dim, cv2.INTER_AREA) # We resize the frame
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) # We apply a black & white filter
        gray = cv2.GaussianBlur(gray, (21, 21), 0) # Then we blur the picture

        # if the first frame is None, initialize it because there is no frame for comparing the current one with a previous one
        if past_frame is None:
            past_frame = gray
            return past_frame

        # check if past_frame and current have the same sizes
        (h_past_frame, w_past_frame) = past_frame.shape[:2]
        (h_current_frame, w_current_frame) = gray.shape[:2]
        if h_past_frame != h_current_frame or w_past_frame != w_current_frame: # This shouldnt occur but this is error handling
            logger.error('Past frame and current frame do not have the same sizes {0} {1} {2} {3}'.format(h_past_frame, w_past_frame, h_current_frame, w_current_frame))
            return

        # Detect when too dark to reduce false alarms
        if self.camera.digital_gain == Fraction(187/128) and self.camera.analog_gain == Fraction(8):
            if not self.too_dark_message_printed:
                logger.info("Too dark to run motion detection")
                self.too_dark_message_printed = True
            return None
        else:
            self.too_dark_message_printed = False

        # compute the absolute difference between the current frame and first frame
        frame_delta = cv2.absdiff(past_frame, gray)
        # then apply a threshold to remove camera motion and other false positives (like light changes)
        thresh = cv2.threshold(frame_delta, 50, 255, cv2.THRESH_BINARY)[1]

        # dilate the thresholded image to fill in holes, then find contours on thresholded image
        thresh = cv2.dilate(thresh, None, iterations=2)
        cnts = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        cnts = cnts[0] if imutils.is_cv2() else cnts[1]

        # loop over the contours
        for c in cnts:
            # if the contour is too small, ignore it
            countour_area = cv2.contourArea(c)

            if countour_area < self.motion_detection_threshold:
                continue

            logger.info("Motion detected! Motion level is {0}, threshold is {1}".format(countour_area, self.motion_detection_threshold))
            # Motion detected because there is a contour that is larger than the specified self.motion_detection_threshold
            # compute the bounding box for the contour, draw it on the frame,
            (x, y, w, h) = cv2.boundingRect(c)
            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
            self.handle_motion_detected(frame)

        return None

    def handle_motion_detected(self, frame):
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        bounding_box_path = '{0}/rpi-security-{1}-box.jpeg'.format(self.camera_save_path, timestamp)
        cv2.imwrite(bounding_box_path, frame)
        self.queue.put(bounding_box_path)
        self.trigger_camera()
        return

    def stop_motion_detection(self):
        try:
            if self.motion_detection_running:
                logger.debug("Stopping motion detection")
                self.motion_detection_running = False
            if not self.camera.recording:
                return
            else:
                self.camera.stop_recording()
        except Exception as e:
            logger.error('Error in stop_motion_detection: {0}'.format(repr(e)))

    def clear_queue(self):
        with self.queue.mutex:
            self.queue.queue.clear()
