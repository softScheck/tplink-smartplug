#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
if [ $# -ne 1 ]
  then
    echo "Usage: settime.sh <MAC>"
    echo "Important: Contact must have been made, so that MAC address is in arp table"
        exit 1
fi

IP=$(arp -n | grep -i $1 | grep -oP '^[^\s]+')

$DIR/settime.sh $IP