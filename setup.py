from setuptools import setup

setup(
    name = 'rpi-security',
    version = '0.8',
    author = 'Max Williams',
    author_email = 'futuresharks@gmail.com',
    url = 'https://github.com/FutureSharks/rpi-security',
    license = 'GPLv2',
    description = 'A security system written in python to run on a Raspberry Pi with motion detection and mobile notifications',
    long_description = open('README.md', encoding='utf-8').read(),
    packages = [
        'rpisec',
        'rpisec/threads'
    ],
    scripts = ['bin/rpi-security.py'],
    data_files = [
        ('/lib/systemd/system', ['etc/rpi-security.service']),
        ('/etc', ['etc/rpi-security.conf']),
        ('/var/lib/rpi-security', ['etc/data.yaml'])
    ],
    install_requires = [
        'python-telegram-bot',
        'picamera',
        'RPi.GPIO',
        'numpy',
        'configparser',
        'requests',
        'requests[security]',
        'netaddr',
        'netifaces',
        'pyyaml',
        'scapy-python3',
        'Pillow'
    ],
    classifiers = [
        'Environment :: Console',
        'Topic :: Security',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3 :: Only'
    ],
)
