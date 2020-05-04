#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "Usage: settime.sh IP1 IP2 ..."
        exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Set Timezone
# {"time":{"set_timezone":{"year":2016,"month":1,"mday":1,"hour":10,"min":10,"sec":10,"index":42}}}

for i in "$@"
do 
	jahr=$(date +"%Y")
	monat=$(date +"%m")
	tag=$(date +"%d")
	stunde=$(date +"%-H")
	minute=$(date +"%-M")
	sekunde=$(date +"%-S")
	echo $DIR/tplink_smartplug.py -t $i -j "{\"time\":{\"set_timezone\":{\"year\":$jahr,\"month\":$monat,\"mday\":$tag,\"hour\":$stunde,\"min\":$minute,\"sec\":$sekunde,\"index\":42}}}"
	$DIR/tplink_smartplug.py -t $i -j "{\"time\":{\"set_timezone\":{\"year\":$jahr,\"month\":$monat,\"mday\":$tag,\"hour\":$stunde,\"min\":$minute,\"sec\":$sekunde,\"index\":42}}}"
done