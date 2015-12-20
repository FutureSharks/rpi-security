# Raspberry Pi Security System

A security system written in python to run on a [Raspberry Pi Model A+](https://www.raspberrypi.org/products/model-a-plus/).

Features:
  - Motion triggered photo
  - Mobile notifications
  - Intelligent sensing of whether people are home or not

Written in Python.

Similar to:

  https://www.kickstarter.com/projects/vivienmuller/ulo/

  http://canary.is/

## Mobile phone detection

Doesn't require monitor mode. Uses [scapy](http://www.secdev.org/projects/scapy/) to send ARP scan to mobile phone MAC addresses to detect presence.

## Notifications

Uses [Pushbullet](https://www.pushbullet.com/) which allows for two way communication from mobile device to rpi-security system. Can also be used in a browser. Has excellent syncing.

## Photos

![rpi-security 1](../master/images/rpi-security-1.jpg?raw=true)
