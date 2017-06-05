# -*- coding: utf-8 -*-

import logging
import time


logger = logging.getLogger()


def monitor_alarm_state(rpis, camera):
    """
    This function monitors and updates the alarm state, starts/stops motion detection when
    state is armed and takes photos when motion detection is triggered.
    """
    logger.info("thread running")
    while True:
        time.sleep(0.1)
        rpis.state.check()
        if rpis.state.current == 'armed':
            while not camera.lock.locked():
                camera.start_motion_detection()
                rpis.state.check()
                if rpis.state.current is not 'armed':
                    break
                if camera.motion_detector.camera_trigger.is_set():
                    camera.stop_motion_detection()
                    camera.trigger_camera()
                    camera.motion_detector.camera_trigger.clear()
            else:
                camera.stop_motion_detection()
        else:
            camera.stop_motion_detection()
