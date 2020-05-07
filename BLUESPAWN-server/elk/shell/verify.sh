#!/bin/bash

curl --cacert /certs/ca/ca.crt -u elastic 'https://elasticsearch:9200/_cat/nodes?v'