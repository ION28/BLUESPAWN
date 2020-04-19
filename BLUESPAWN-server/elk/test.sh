#!/bin/bash

echo IN MY SCRIPT YAAAY

# Randomly generate passwords and store the output
pass=$(echo y | ./opt/elasticsearch/bin/elasticsearch-setup-passwords auto)
echo PASSWORDS: "$pass"

# Parse the kibana passwords
kibana=$(echo "$pass" | grep kibana)
echo KIBANA PASSWORD: "$kibana"

# Wait endlessly so the container doesn't die
wait