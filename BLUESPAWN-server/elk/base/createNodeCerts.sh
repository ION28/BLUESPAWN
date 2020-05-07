#!/bin/bash
set -xe

node_name="$1"
dns="$2"
pass=$(cat pass)
echo "instances:" > input.yml
echo "  - name: '$node_name'" >> input.yml
echo "    dns: [ '$dns']" >> input.yml

echo '#!/usr/bin/expect' > tmp_createNodeCerts.sh
echo "spawn ./runCertGen.sh --days 1095 --cert /certs/ca/ca.crt --key /certs/ca/ca.key --pass --in /certs/input.yml --out /certs/$node_name.zip" >> tmp_createNodeCerts.sh
echo 'expect "Enter password for CA private key: "' >> tmp_createNodeCerts.sh
echo "send \"$pass\n\"" >> tmp_createNodeCerts.sh
echo "sleep 5" >> tmp_createNodeCerts.sh
chmod +x tmp_createNodeCerts.sh
./tmp_createNodeCerts.sh
rm tmp_createNodeCerts.sh

rm input.yml