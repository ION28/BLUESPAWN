#!/bin/bash
set -xe

# RUN mkdir /certs
apt update
apt install openssl -y
apt install unzip -y;
apt install expect -y;
apt install ca-certificates -y;

cd /certs
echo "long password for the CA" > pass
pass=$(cat pass)

# Generate CA from password
sed "s/password_var/$pass/g" createCA.sh > t
mv t createCA.sh
chmod +x createCA.sh
./createCA.sh
unzip ca.zip

# Generate server certificates
./createNodeCerts.sh elk elasticsearch
unzip elk.zip
./createNodeCerts.sh logstash logstash
unzip logstash.zip
./createNodeCerts.sh kibana kibana
unzip kibana.zip

# Configure Elasticsearch
cd /etc/elasticsearch
mkdir certs
cp /certs/ca/ca.crt /certs/elk/* certs
config="xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true
xpack.http.ssl.key: certs/elk.key
xpack.http.ssl.certificate: certs/elk.crt
xpack.http.ssl.certificate_authorities: certs/ca.crt
xpack.security.http.ssl.key: certs/elk.key
xpack.security.http.ssl.certificate: certs/elk.crt
xpack.security.http.ssl.certificate_authorities: certs/ca.crt
xpack.security.transport.ssl.key: certs/elk.key
xpack.security.transport.ssl.certificate: certs/elk.crt
xpack.security.transport.ssl.certificate_authorities: certs/ca.crt
node.max_local_storage_nodes: 2
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.http.ssl.verification_mode: certificate" 
echo "$config" >> elasticsearch.yml

# Configure Kibana
cd /opt/kibana
mkdir certs
cp /certs/ca/ca.crt /certs/kibana/* certs
kibana_config='server.ssl.enabled: true
server.ssl.certificate: certs/kibana.crt
server.ssl.key: certs/kibana.key
elasticsearch.hosts: ["https://elasticsearch:9200"]
elasticsearch.username: "kibana"
elasticsearch.password: "Chiapet1"
elasticsearch.ssl.verificationMode: certificate
elasticsearch.ssl.certificateAuthorities: [ "certs/ca.crt" ]
xpack.security.encryptionKey: "some_really_long_phrase_no_one_can_guess_haha"
'
echo "$kibana_config" >> /opt/kibana/config/kibana.yml

# Configure logstash
openssl pkcs8 -in /certs/logstash/logstash.key -topk8 -nocrypt -out /certs/logstash/logstash.pkcs8.key
cd /opt/logstash
logstash_config='node.name: logstash
xpack.monitoring.enabled: true
xpack.monitoring.elasticsearch.username: logstash_system
xpack.monitoring.elasticsearch.password: "Chiapet1"
xpack.monitoring.elasticsearch.hosts: [ 'https://elasticsearch:9200' ]
xpack.monitoring.elasticsearch.ssl.certificate_authority: /certs/ca/ca.crt
'

echo "$logstash_config" >> /opt/logstash/config/logstash.yml