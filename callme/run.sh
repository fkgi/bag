#!/bin/bash

# curl http://localhost:8080 -v

ST=`date "+%H:%M:%S.%3N"`

for ((i=0; i < 1000; i++)); do
    ./callme -U http://naf.mnc99.mcc999.3gppnetwork.org/path -i 999991122223333@ims.mnc99.mcc999.3gppnetwork.org -u sip:+9991122223333@ims.mnc99.mcc999.3gppnetwork.org
done

echo ${ST}
date "+%H:%M:%S.%3N"

exit 0