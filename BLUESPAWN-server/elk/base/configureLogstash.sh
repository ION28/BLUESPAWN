#!/bin/bash
set -xe

sleep 60

curl --cacert /certs/ca/ca.crt -k --user elastic:"Chiapet1" -X POST "https://elasticsearch:9200/_security/role/logstash_write_role" -H 'Content-Type: application/json' -d'
{
  "cluster": [
      "monitor",
      "manage_index_templates"
    ],
    "indices": [
      {
        "names": [
          "logstash*"
        ],
        "privileges": [
          "write",
          "create_index"
        ],
        "field_security": {
          "grant": [
            "*"
          ]
        }
      }
    ],
    "run_as": [],
    "metadata": {},
    "transient_metadata": {
      "enabled": true
    }
}
'

curl --cacert /certs/ca/ca.crt -k --user elastic:"Chiapet1" -X POST "https://elasticsearch:9200/_security/user/logstash_writer" -H 'Content-Type: application/json' -d'
{
  "username": "logstash_writer",
  "roles": [
    "logstash_write_role"
  ],
  "full_name": null,
  "email": null,
  "password": "Chiapet1",
  "enabled": true
}
'

rm /etc/logstash/conf.d/*
echo 'input {
  beats {
    port => 5044
    ssl => true
    ssl_key => "/certs/logstash/logstash.pkcs8.key"
    ssl_certificate => "/certs/logstash/logstash.crt"
  }
}
output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    cacert => "/certs/ca/ca.crt"
    user => "elastic"
    password => Chiapet1
  }
}' > /etc/logstash/conf.d/example.conf