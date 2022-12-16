#!/usr/bin/env python3

import sys
from scapy.all import PcapReader, re, Raw, TCP, UDP


VALID_METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH"
]  # see https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods


def payload2curl(p):
    try:
        lines = re.compile("[\n\r]+").split(p.decode())
    except UnicodeDecodeError:
        print(f"This packet cant be decoded because uses non printable ASCII characters: {str(p)}")
        return False

    start_line = re.search("^([A-Z]+) ([^ ]+) (HTTP\/[0-9\/]+)", lines[0])
    method = start_line.group(1)
    url = start_line.group(2)
    version = start_line.group(3)  # Never used

    if method not in VALID_METHODS:
        return

    del lines[0]
    headers = []
    for line in lines:
        if ":" in line:
            headers.append("-H '{}'".format(line))
        if re.match("^Host:", line, re.I):
            host_header = re.search("^Host: (.*)", line, re.I)
            host_name = host_header.group(1)

    proto_host = 'http://{}/'.format(host_name)
    if not url.startswith(proto_host):
        url = "{}{}".format(proto_host, url[1:] if url[0] == "/" else url)
    curl = "curl '{}' \\\n -X {} \\\n ".format(url, method)
    curl += " \\\n ".join(headers)
    return curl


def main():
    if len(sys.argv) != 2:
        print (f"Usage: {sys.argv[0]} inputfilename")
        return

    infile = sys.argv[1]

    with PcapReader(infile) as packets:
        for p in packets:
            if (p.haslayer(TCP) or p.haslayer(UDP)) and p.haslayer(Raw):
                cmd = payload2curl(p[Raw].load)
                if cmd:
                    print(cmd)
                else:
                    print("Bad packet:\n\t" + p.show(dump=True).replace('\n', '\n\t'))


if __name__ == "__main__":
    main()
