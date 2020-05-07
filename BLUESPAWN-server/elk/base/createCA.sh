#!/usr/bin/expect

spawn ./runCertGen.sh --dn "CN=BLUESPAWN" --pass --days 3650 --keysize 4096 --out /certs/ca.zip
expect "Enter password for CA private key: "
send "password_var\n"
expect "Enter instance name: "
send "\n"
expect "Would you like to specify another instance? Press 'y' to continue entering instance information: "
send "\n"
sleep 5