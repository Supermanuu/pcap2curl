#!/bin/bash
set -ex

[ -z "$1" ] && echo "Usage: $(basename $0) file" && exit 2

FILE="$1"

docker run -v "$FILE:/capture.pcap" pcap2curl /pcap2curl/pcap2curl.py /capture.pcap
