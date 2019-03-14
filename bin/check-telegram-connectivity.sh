#!/bin/sh

HOST="api.telegram.org"
RETRY=5

for run in $(seq 1 $RETRY); do
  if /usr/bin/host api.telegram.org > /dev/null 2>1; then
      exit 0
  fi
  sleep 10
done

/usr/bin/logger "Rebooting due to connectivity issue"
/sbin/shutdown -r now

exit 0
