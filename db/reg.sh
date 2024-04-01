curl -v http://localhost:8080

curl -v -X PUT http://localhost:8080/999991122223333@ims.mnc99.mcc999.3gppnetwork.org -d '
{
    "RAND":"5cc0188ec5ff0ce0bfe386f67f46ae56",
    "AUTN":"8ea42e12aff7815a5692ed5ea939d872",
    "RES":"5831ff26f982909239694ccb76071879",
    "IK":"d75a4e49ac0fa59884484cbcfe4cf5bf",
    "CK":"0d5ec968ea653ad4841a7a92b70752ab"
}'

curl -v -X PUT http://localhost:8080/999991122223333@ims.mnc99.mcc999.3gppnetwork.org -d '
{
    "RAND":"5cc0188ec5ff0ce0bfe386f67f46ae56",
    "AUTN":"8ea42e12aff7815a5692ed5ea939d872",
    "RES":"5831ff26f982909239694ccb76071879",
    "IK":"d75a4e49ac0fa59884484cbcfe4cf5bf",
    "CK":"0d5ec968ea653ad4841a7a92b70752ab"
}'

curl -v -X PUT http://localhost:8080/999991122223333@ims.mnc99.mcc999.3gppnetwork.org -d '{}'

curl -v -X DELETE http://localhost:8080/999991122223333@ims.mnc99.mcc999.3gppnetwork.org
