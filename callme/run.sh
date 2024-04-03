#!/bin/bash

# curl http://localhost:8080 -v
URI="http://naf.mnc99.mcc999.3gppnetwork.org/path"
IMPIp="99999112222"
IMPIs="@ims.mnc99.mcc999.3gppnetwork.org"
IMPUp="sip:+999112222"
IMPUs="@ims.mnc99.mcc999.3gppnetwork.org"

ST=`date "+%H:%M:%S.%3N"`

for i in $(seq -w 1 1000); do
    ./callme -uri ${URI} -impi ${IMPIp}${i}${IMPIs} -impu ${IMPUp}${i}${IMPUs} -clear
    ./callme -uri ${URI} -impi ${IMPIp}${i}${IMPIs} -impu ${IMPUp}${i}${IMPUs}
done

echo ${ST}
date "+%H:%M:%S.%3N"

exit 0

# ./callme -uri http://naf.mnc99.mcc999.3gppnetwork.org/path -impi 999991122220001@ims.mnc99.mcc999.3gppnetwork.org -impu sip:+9991122220001@ims.mnc99.mcc999.3gppnetwork.org