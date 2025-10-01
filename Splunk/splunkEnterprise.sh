#!/bin/bash

# Define variables
SPLUNK_VERSION="9.3.2"
SPLUNK_BUILD="d8bb32809498"
SPLUNK_PACKAGE="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}-Linux-x86_64.tgz"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PACKAGE}"

# Download
echo "Downloading Splunk Enterprise ${SPLUNK_VERSION}..."
wget --no-check-certificate -O "$SPLUNK_PACKAGE" "$SPLUNK_URL" || \
    curl -k -o "$SPLUNK_PACKAGE" "$SPLUNK_URL"

echo "Download complete: $SPLUNK_PACKAGE"
