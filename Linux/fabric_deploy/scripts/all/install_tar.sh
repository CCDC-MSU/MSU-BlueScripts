#!/bin/sh
if command -v dnf >/dev/null; then
    dnf install -y tar
elif command -v yum >/dev/null; then
    yum install -y tar
else
    echo "No dnf/yum found"
    exit 1
fi
