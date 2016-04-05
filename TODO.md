# rpi-sec to do list

Switch to Telegram instead of pushbullet

Fix shutdown problem, it shouldn't require 'pkill -9'.

Add a udev rule for monitor interface instead of having it in the systemd service file?

Implement some form of LED indicator where a colour shows the alarm state.

Use two logger handlers, one for syslog, one for console output.

Use a pushbullet channel?

Automatically clean up old photos

Implement an archive feature. Eg copy to S3 or FTP.

Handle pushbullet exceptions in a better way.

Use methods instead of just many functions.

Auto adjust camera settings if too dark, white balance etc
