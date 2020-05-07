# Installation

### Hostnames

The servers use SSL certificate-based authentication, and will only work with proper DNS names. The nmes must be:

```
elasticsearch 	-> elasticsearch
kibana 			-> kibana
logstash 		-> logstash
```

Thus there are two options:

1. Configure a DNS server such that those hostnames point to the server runninf the docker environment.
2. Configure `/etc/hosts` or `C:\Windows\system32\drivers\etc\hosts` on a machine manually to do so.

#### Example /etc/hosts

```
127.0.0.1 elasticsearch
127.0.0.1 kibana
127.0.0.1 logstash
```


# Launching

Launch with `sudo docker-compose up`. Kibana is on port 5601 and Elasticsearch is on port 9200.