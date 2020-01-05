from setuptools import setup

setup(
    name = 'rpi-security',
    version = '1.5',
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
        ('/etc', ['etc/rpi-security.conf', 'etc/rpi-security-environment']),
        ('/var/lib/rpi-security', ['etc/data.yaml'])
    ],
    install_requires = [
        'python-telegram-bot==12.2.0',
        'picamera==1.13',
        'imutils==0.5.2',
        'numpy',
        'configparser',
        'requests',
        'requests[security]',
        'netaddr',
        'netifaces',
        'pyyaml',
        'kamene==0.32',
        'Pillow==6.2.1',
        'opencv-contrib-python==3.4.6.27',
        'opencv-contrib-python-headless==3.4.6.27',
    ],
    classifiers = [
        'Environment :: Console',
        'Topic :: Security',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3 :: Only'
    ],
)
