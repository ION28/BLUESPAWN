#!/bin/bash
set -xe

service elasticsearch start
sleep 20

# Randomly generate passwords and store the output
pass=$(./opt/elasticsearch/bin/elasticsearch-setup-passwords auto -b -u "https://127.0.0.1:9200")

# Parse the kibana passwords
kibana_pass=$(echo "$pass" | grep "PASSWORD kibana" | awk -F' ' '{print $4}')
elastic_pass=$(echo "$pass" | grep "PASSWORD elastic" | awk -F' ' '{print $4}')

curl --cacert /certs/ca/ca.crt -k --user elastic:"$elastic_pass" -X POST "https://127.0.0.1:9200/_xpack/security/user/kibana/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --cacert /certs/ca/ca.crt -k --user elastic:"$elastic_pass" -X POST "https://127.0.0.1:9200/_xpack/security/user/apm_system/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --cacert /certs/ca/ca.crt -k --user elastic:"$elastic_pass" -X POST "https://127.0.0.1:9200/_xpack/security/user/logstash_system/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --cacert /certs/ca/ca.crt -k --user elastic:"$elastic_pass" -X POST "https://127.0.0.1:9200/_xpack/security/user/beats_system/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --cacert /certs/ca/ca.crt -k --user elastic:"$elastic_pass" -X POST "https://127.0.0.1:9200/_xpack/security/user/remote_monitoring_user/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --cacert /certs/ca/ca.crt -k --user elastic:"$elastic_pass" -X POST "https://127.0.0.1:9200/_xpack/security/user/elastic/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'

echo "Passwords Configured"