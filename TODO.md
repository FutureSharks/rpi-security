# To do

- Automatically clean up old photos
- Hard coded `mon0` interface name in `etc/rpi-security.service`
- Update photos now that PIR sensor is not required
- Tidy up comments
- Remove PIR CAD files
- Fig syslog formatting `Dec 22 10:40:02 raspberrypi monitor_alarm_state.py:...` should include service name
- Don't save motion detection related photos to the filesystem, [save directly to OpenCV object](https://picamera.readthedocs.io/en/release-0.6/recipes.html#capturing-to-an-opencv-object)
