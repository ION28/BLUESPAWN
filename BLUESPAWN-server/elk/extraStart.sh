#!/bin/bash
set -xe

# Randomly generate passwords and store the output
pass=$(./opt/elasticsearch/bin/elasticsearch-setup-passwords auto -b)

# Parse the kibana passwords
kibana_pass=$(echo "$pass" | grep "PASSWORD kibana" | awk -F' ' '{print $4}')
elastic_pass=$(echo "$pass" | grep "PASSWORD elastic" | awk -F' ' '{print $4}')

curl --user elastic:"$elastic_pass" -X POST "localhost:9200/_security/user/kibana/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --user elastic:"$elastic_pass" -X POST "localhost:9200/_security/user/apm_system/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --user elastic:"$elastic_pass" -X POST "localhost:9200/_security/user/logstash_system/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --user elastic:"$elastic_pass" -X POST "localhost:9200/_security/user/beats_system/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --user elastic:"$elastic_pass" -X POST "localhost:9200/_security/user/remote_monitoring_user/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'
curl --user elastic:"$elastic_pass" -X POST "localhost:9200/_security/user/elastic/_password?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "Chiapet1"
}
'

echo 'elasticsearch.username: "kibana"' >> opt/kibana/config/kibana.yml
echo 'elasticsearch.password: "Chiapet1"' >> opt/kibana/config/kibana.yml
echo 'xpack.security.encryptionKey: "some_really_long_phrase_no_kne_can_guess_haha"' >> opt/kibana/config/kibana.yml

# Restart kibana
service kibana stop
service kibana start

# Wait endlessly so the container doesn't die
wait