#!/bin/sh
echo "Checking connectivity on $(hostname)..."
ping -c 2 8.8.8.8 || echo "Ping 8.8.8.8 failed"
cat /etc/resolv.conf
curl -I --connect-timeout 5 https://google.com || echo "Curl google failed"
