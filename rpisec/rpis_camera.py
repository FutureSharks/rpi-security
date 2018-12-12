# -*- coding: utf-8 -*-

import logging
import os
import time
from picamera.array import PiMotionAnalysis
from picamera import PiCamera
import numpy as np
from PIL import Image
from threading import Lock, Event
from queue import Queue
from .exit_clean import exit_error
from datetime import datetime

# from imutils.video import VideoStream
import imutils
import time
import cv2

logger = logging.getLogger()


class RpisCamera(object):
    '''
    A wrapper for the camera. Runs motion detection, provides a queue for photos,
    captues photos and GIFs.
    '''
    def __init__(self, photo_size, gif_size, motion_size, camera_vflip,
            camera_hflip, motion_detection_setting, camera_capture_length,
            camera_mode):
        self.photo_size = photo_size
        self.gif_size = gif_size
        self.camera_vflip = camera_vflip
        self.camera_hflip = camera_hflip
        self.lock = Lock()
        self.queue = Queue()
        self.motion_magnitude = motion_detection_setting[0]
        self.motion_vectors = motion_detection_setting[1]
        self.motion_framerate = 5
        self.motion_size = motion_size
        self.temp_directory = '/var/tmp'
        self.camera_save_path = '/var/tmp'
        self.camera_capture_length = camera_capture_length
        self.camera_mode = camera_mode

        try:
            self.camera = PiCamera()
            self.camera.vflip = self.camera_vflip
            self.camera.hflip = self.camera_hflip
            self.camera.led = False
        except Exception as e:
            exit_error('Camera module failed to intialise with error {0}'.format(repr(e)))

    def take_photo(self, filename_extra_suffix=''):
        """
        Captures a photo and saves it disk.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        photo = '{0}/rpi-security-{1}{2}.jpeg'.format(self.camera_save_path, timestamp, filename_extra_suffix)
        try:
            self.set_normal_settings()
            with self.lock:
                while self.camera.recording:
                    time.sleep(0.1)
                time.sleep(2)
                self.camera.resolution = self.photo_size
                self.camera.capture(photo, use_video_port=False)
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
            self.set_normal_settings()
            for jpeg in jpeg_files:
                with self.lock:
                    while self.camera.recording:
                        time.sleep(0.1)
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

    def set_normal_settings(self):
        self.camera.awb_mode = 'auto'
        self.camera.exposure_mode = 'auto'

    def set_motion_settings(self):
        self.camera.resolution = self.motion_size
        self.camera.framerate = self.motion_framerate
        exposure_speed = self.camera.exposure_speed
        awb_gains = self.camera.awb_gains
        self.camera.shutter_speed = exposure_speed
        self.camera.awb_mode = 'off'
        self.camera.awb_gains = awb_gains
        self.camera.exposure_mode = 'off'

    def start_motion_detection(self, rpis):
        min_area = 500
        past_frame = None
        logger.debug("Started motion detection from video stream from RpiCamera")
        # loop over the frames of the video
        picture_path = '/tmp/rpi-security-current.jpg'
        while not self.lock.locked() and rpis.state.current == 'armed':
            self.camera.resolution = self.motion_size
            self.camera.capture(picture_path, use_video_port=False)
            time.sleep(0.3)
            # grab the current frame
            frame = cv2.imread(picture_path)

            # if frame is initialized, we have not reach the end of the video
            if frame is not None:
                past_frame = self.handle_new_frame(frame, past_frame, min_area)
            else:
                logger.error("No more frame")
            rpis.state.check()
        else:
            self.stop_motion_detection()

    def handle_new_frame(self, frame, past_frame, min_area):
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

        # compute the absolute difference between the current frame and first frame
        frame_detla = cv2.absdiff(past_frame, gray)
        # then apply a threshold to remove camera motion and other false positives (like light changes)
        thresh = cv2.threshold(frame_detla, 50, 255, cv2.THRESH_BINARY)[1]

        # dilate the thresholded image to fill in holes, then find contours on thresholded image
        thresh = cv2.dilate(thresh, None, iterations=2)
        cnts = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        cnts = cnts[0] if imutils.is_cv2() else cnts[1]

        # loop over the contours
        for c in cnts:
            # if the contour is too small, ignore it
            if cv2.contourArea(c) < min_area:
                continue

            logger.debug("Motion detected !") # Motion detected because there is a contour that is larger than the specified min_area
            # compute the bounding box for the contour, draw it on the frame,
            (x, y, w, h) = cv2.boundingRect(c)
            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
            self.handle_motion_detected(frame, gray, frame_detla, thresh)

        return None

    def handle_motion_detected(self, frame, gray, frame_detla, thresh):
        frame_path = self.print_image("frame", frame)
        self.queue.put(frame_path)
        self.trigger_camera()

        # In case of motion detection, the pictures will be saved in /tmp folder to get the files somewhere else than Telegram
        # Note that gray, abs_diff and thresh can be used to debug in case of false alarm
        self.print_image("gray", gray)
        self.print_image("abs_diff", frame_detla)
        self.print_image("thresh", thresh)
        return

    # Usefull function for saving images in /tmp folder.
    def print_image(self, name, image):
        path = '/tmp/' + name + '_' + datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + ".jpeg"
        cv2.imwrite(path, image)
        return path

    def stop_motion_detection(self):
        try:
            if not self.camera.recording:
                return
            else:
                logger.debug("Stopping motion detection")
                self.camera.stop_recording()
        except Exception as e:
            logger.error('Error in stop_motion_detection: {0}'.format(repr(e)))

    def clear_queue(self):
        with self.queue.mutex:
            self.queue.queue.clear()
