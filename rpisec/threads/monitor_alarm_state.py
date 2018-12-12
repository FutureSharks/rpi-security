# -*- coding: utf-8 -*-

import logging
import time

logger = logging.getLogger()


def monitor_alarm_state(rpis, camera):
	"""
	This function monitors and updates the alarm state, starts/stops motion detection when
	state is armed and takes photos when motion detection is triggered.
	"""
	logger.info("Monitoring thread running")
	time.sleep(2.0)
	while True:
		time.sleep(0.1)
		rpis.state.check()
		if rpis.state.current == 'armed':
			camera.start_motion_detection(rpis)
		else:
			camera.stop_motion_detection()
