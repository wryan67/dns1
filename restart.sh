#!/bin/sh
# Bounce the dns1 JVM by restarting the gandolf container.
#
# The jar lives on the /var/www bind mount, so a new file is visible as soon
# as it is copied. SIGHUP only reloads the domain caches; it does not load a
# new jar. entrypoint.sh is PID 1 and exits the container if the JVM exits,
# and the container is started with --restart unless-stopped, so restarting
# gandolf is the bounce that comes back up. Apache is in the same container
# and drops for the same few seconds.
set -eu

docker --context elrond restart gandolf

i=0
while [ "$i" -lt 60 ]; do
    if docker --context elrond exec gandolf sh -c 'ps -ef | grep -v grep | grep -q "[/]var/www/dns1/dns1.jar"'; then
        echo "dns1 is running"
        exit 0
    fi
    i=$((i + 1))
    sleep 1
done

echo "dns1 did not come back within 60s" >&2
exit 1
