from setuptools import setup

setup(
    name='rpi-security',
    version='0.2',
    author=u'Max Williams',
    author_email='futuresharks@gmail.com',
    url='https://github.com/FutureSharks/rpi-security',
    license='GPLv2',
    description='A security system written in python to run on a Raspberry Pi with motion detection and mobile notifications',
    long_description=open('README.md').read(),
    scripts = [ 'bin/rpi-security.py' ],
    data_files=[
        ('/lib/systemd/system', ['etc/rpi-security.service']),
        ('/etc', ['etc/rpi-security.conf'])
    ],
    install_requires=[
        'python-telegram-bot',
        'picamera',
        'netaddr',
        'requests',
        'requests[security]',
        'netifaces'
    ],
    classifiers=[
    'Environment :: Console',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7'
    ],
)
