# Raspberry Pi Security System

A simple security system to run on a [Raspberry Pi](https://www.raspberrypi.org/).

Features:
  - Motion triggered image capture.
  - Mobile notifications with images.
  - Detects when you are home and arms or disarms automatically.
  - Can be remotely disabled or queried for status using pushbullet app.

Similar to these products:

  - https://www.kickstarter.com/projects/vivienmuller/ulo/
  - http://canary.is/

![rpi-security 1](../master/images/rpi-security-1.jpg?raw=true)

## Requirements

You will need this hardware:
  - Raspberry Pi with camera interface.
  - Raspberry Pi camera module.
  - PIR sensor module. Any generic HC SR501 (or similar) module should work. Example [from Adafruit](https://www.adafruit.com/products/189).
  - USB Wi-Fi that supports monitor mode. I used a RT5370 based adapter, they are cheap at about €6 and easy to find.
  - An enclosure of some sort. Details of the hardware I made is [here](hardware).

Other requirements:
  - A [Pushbullet account](https://www.pushbullet.com). A free account works fine.
  - Raspbian distribution installed. I used Jessie. You could possibly use a different OS but I havn't tried it.
  - Python 2.7.

## How it works

### Automatic presence detection

One of my main goals was to have the system completely automatic. I didn't want to have to arm or disarm it when leaving or arriving home. I figured the easiest way to achieve this was to try and detect the mobile phones of the home occupants. Conceptually this was quite simple but in practice it was the most challenging part because:
  - Capturing all packets on a Wi-Fi interface is too resource intensive.
  - There are presently no good 5Ghz USB Wi-Fi adapters that support monitor mode. This means packet monitoring is restricted to 2.4Ghz where most modern mobile phones use 5Ghz now.
  - Mobile phones are not always online and sending packets over Wi-Fi. Sometimes they stay unconnected for 15 minutes or longer.
  - Even with 99% accuracy false alarms are annoying.

After much testing I used an approach that mixes active (ARP scan) and passive (packet capture) detection over the Wi-Fi adapter based on knowing the MAC addresses of the mobile phones. The mobile phone MAC addresses are set in the configuration and the rpi-security application captures packets on a monitor mode interface with the following filter:
1. Wi-Fi probe requests from any of the configured MACs.
2. Any packets sent from the configured MACs to the host running rpi-security.

The application resets a counter when packets are detected and if the counter goes longer than ~10 minutes the system is armed. To eliminate the many false alarms, when transitioning from armed to disarmed state or vice versa, the application performs an ARP scan directed at each of the configured MAC addresses to be sure they are definitely online or offline. Both iOS and Android will respond to this ARP scan 99% of the time where a ICMP ping is quite unreliable. By combining the capture of Wi-Fi probe requests and using ARP scanning, the Wi-Fi frequency doesn't matter because mobile phones send probe requests on both frequencies and ARP scan works across both frequencies too.

### Notifications

[Pushbullet](https://www.pushbullet.com/) is used to send notifications with the captured images. They have good mobile applications and a nice API. You can also view the messages in a browser and messages are synced.

If the system is in an armed state and motion is detected then a message with the captured image is sent to your mobile phone.

Notifications are also sent on any state change.

![rpi-security 2](../master/images/rpi-security-notification.png?raw=true)

### Remote control

The application checks Pushbullet messages every 10 minutes for specific messages that trigger certain actions. If this checking happens at a higher frequency then you will hit the Pushbullet API rate limit unless you switch to a paid account.

If you send a message with just the text 'disable' then the system will be disabled until the message is deleted:

![rpi-security 3](../master/images/rpi-security-disable-message.png?raw=true)


You can also send a 'status' message to get information about the current state:

![rpi-security 4](../master/images/rpi-security-status-message.png?raw=true)

### Python

I wrote the whole application in python. Large parts of the functionality are provided by the following pip modules:
  - [picamera](https://github.com/waveform80/picamera)
  - [Scapy](http://www.secdev.org/projects/scapy/)
  - [Pushbullet](https://github.com/randomchars/pushbullet.py)

The application uses multithreading in order to process events asynchronously. There is a thread for mobile phone packet detection, processing the capture photos, monitoring the alarm state and monitoring the PIR sensor.

## Installation, configuration and Running

First install required packages:

        sudo apt-get install tcpdump iw python-dev python-pip

Optionally, update pip:

        pip install --upgrade pip

To install, use pip:

        sudo pip install https://github.com/secdev/scapy/zipball/master
        sudo pip install https://github.com/FutureSharks/rpi-security/zipball/master
        sudo systemctl daemon-reload
        sudo systemctl enable rpi-security.service

Add your MAC address or addresses and Pushbullet API key to ``/etc/rpi-security.conf``.

Ensure you have enabled the camera module using ``raspi-config``.

And start the service:

      sudo systemctl start rpi-security.service

It runs as a service and logs to syslog. To see the logs it generates check ``/var/log/syslog``.

There is also a debug option that logs to stdout:

        root@raspberrypi:~# iw phy phy0 interface add mon0 type monitor
        root@raspberrypi:~# /usr/local/bin/rpi-security.py -d
        Mar 16 22:26:13 rpi-security(MainThread): Calculated network: 192.168.178.0/24
        Mar 16 22:26:13 rpi-security(monitor_alarm_state): thread running
        Mar 16 22:26:13 rpi-security(capture_packets): thread running
        Mar 16 22:26:13 rpi-security(process_photos): thread running
        Mar 16 22:26:15 rpi-security(MainThread): rpi-security running
        Mar 16 22:26:51 rpi-security(Dummy-1): Motion detected but current_state is: disarmed
        Mar 16 22:48:24 rpi-security(capture_packets): Packet detected from aa:aa:aa:bb:bb:bb
        Mar 16 22:52:54 rpi-security(capture_packets): Packet detected from aa:aa:aa:bb:bb:bb
