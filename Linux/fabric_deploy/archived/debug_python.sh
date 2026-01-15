#!/bin/sh
echo "Debugging Python installation..."
ls -R /root/python/
echo "---"
ls -la /root/python/bin/python3.12 2>/dev/null
echo "---"
/root/python/bin/python3.12 --version
echo "---"
if command -v ldd >/dev/null 2>&1; then
    ldd /root/python/bin/python3.12
else
    echo "ldd not found"
fi
