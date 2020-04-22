#!/bin/bash

##################################################
# AUTHOR: coulson <fallboyz@umount.net>
# WEBSITE: https://umount.net
# Description：nginx monitoring on zabbix
# Note：Zabbix 2.2 or higher
# DateTime: 2014-11-22
##################################################

# Zabbix requested parameter
KEYNAME="$1"

# Nginx defaults
STATUS_URL="http://localhost:10061/nginx_status"
WGET="/usr/bin/wget"
CURL="/usr/bin/curl"

if [ ! -f $WGET ];
then
    USE_CURL=true
fi

ERROR_PARAM="0.0009"
ERROR_DATA="0.0008"

if [ ! $USE_CURL = true ]; then
    STATS=$($WGET -q $STATUS_URL -O - 2> /dev/null)
else
    STATS=$($CURL -S -s $STATUS_URL)
fi

if [ $? -ne 0 -o -z "$STATS" ]; then
    echo $ERROR_DATA
    exit 1
fi

case $KEYNAME in
    active_connections)
        echo "$STATS" | head -1             | awk '{print $3}'
        ;;
    accepted_connections)
        echo "$STATS" | grep -Ev '[a-zA-Z]' | awk '{print $1}'
        ;;
    handled_connections)
        echo "$STATS" | grep -Ev '[a-zA-Z]' | awk '{print $2}'
        ;;
    handled_requests)
        echo "$STATS" | grep -Ev '[a-zA-Z]' | awk '{print $3}'
        ;;
    reading)
        echo "$STATS" | tail -1             | awk '{print $2}'
        ;;
    writing)
        echo "$STATS" | tail -1             | awk '{print $4}'
        ;;
    waiting)
        echo "$STATS" | tail -1             | awk '{print $6}'
        ;;
    *)
        echo $ERROR_PARAM
        exit 1
        ;;
esac

exit 0
