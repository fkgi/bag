#!/bin/bash

# curl http://localhost:8080 -v
URI="http://naf.mnc99.mcc999.3gppnetwork.org/path"
IMPI="999991122223333@ims.mnc99.mcc999.3gppnetwork.org"
IMPU="sip:+9991122223333@ims.mnc99.mcc999.3gppnetwork.org"

ST=`date "+%H:%M:%S.%3N"`

for ((i=0; i < 1000; i++)); do
    ./callme -uri ${URI} -impi ${IMPI} -impu ${IMPU} -clear
done

echo ${ST}
date "+%H:%M:%S.%3N"

exit 0