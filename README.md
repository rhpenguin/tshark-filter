# tshark filter

A tshark wrapper tool to filter and/or aggregate packat data in PCAP, generate [ECS](https://github.com/elastic/ecs) fields and output them in JSON format. As outputs, currently the followings are supported:
* Stdout
* Elasticsearch

### Output JSON
Output JSON includes:
* Filtered packet fields
* Aggregated packet fields
* [Elastic Common Schema (ECS)](https://github.com/elastic/ecs) fields are generated.

### Example outputs

```
[
...
{
  "@timestamp": "2020-03-22T07:05:22.939Z",
  "agent": {
    "type": "tshark-filter"
  },
  "destination": {
    "domain": "192.168.1.1",
    "ip": "192.168.1.1",
    "port": 80
  },
  "event": {
    "created": "2020-03-22T16:28:54.000Z",
    "module": "pcap",
    "type": "protocol"
  },
  "file": {
    "name": "examples/http2.pcapng"
  },
  "network": {
    "bytes": 441,
    "community_id": "1:Zlod455Wgx3PLiShBIQxxxxxxxx=",
    "iana_number": "6",
    "packets": 1,
    "protocol": "http",
    "related": {
      "ip": [
        "192.168.1.1",
        "192.168.2.1"
      ]
    },
    "transport": "tcp",
    "type": "ipv4"
  },
  "packet": {
    "frame_interface_name": "eth0",
    "frame_len": "441",
    "frame_number": "20",
    "frame_protocols": "eth:ethertype:ip:tcp:http",
    "frame_time_delta": "0.000132512",
    "frame_time_epoch": "1584860722.939166033",
    "frame_time_relative": "1.670992815",
    "http_host": "192.168.1.1",
    "http_request_method": "GET",
    "http_request_uri": "/text.exe",
    "ip_dst": "192.168.1.1",
    "ip_dst_host": "192.168.1.1",
    "ip_len": "427",
    "ip_proto": "6",
    "ip_src": "192.168.2.1",
    "ip_src_host": "192.168.2.1",
    "ip_version": "4",
    "tcp_ack": "1",
    "tcp_dstport": "80",
    "tcp_flags": "0x00000018",
    "tcp_len": "375",
    "tcp_nxtseq": "376",
    "tcp_seq": "1",
    "tcp_srcport": "44208"
  },
  "source": {
    "domain": "192.168.2.1",
    "ip": "192.168.2.1",
    "port": 44208
  }
},
...
]
```

```
[
...
{
  "@timestamp": "2020-03-06T12:30:57.813Z",
  "agent": {
    "type": "tshark-filter"
  },
  "destination": {
    "domain": "192.168.0.1",
    "ip": "192.168.0.1",
    "port": 443
  },
  "event": {
    "created": "2020-03-22T16:20:32.000Z",
    "module": "pcap",
    "type": "protocol"
  },
  "file": {
    "name": "examples/http1.pcapng"
  },
  "network": {
    "bytes": 251,
    "community_id": "1:9Us4XWwcOkDl1xAE6xlxxxxxxxx=",
    "iana_number": "6",
    "packets": 1,
    "protocol": "tls",
    "related": {
      "ip": [
        "192.168.1.1",
        "192.168.0.1"
      ]
    },
    "transport": "tcp",
    "type": "ipv4"
  },
  "packet": {
    "frame_interface_name": "ens33",
    "frame_len": "251",
    "frame_number": "2422",
    "frame_protocols": "eth:ethertype:ip:tcp:tls",
    "frame_time_delta": "0.002324240",
    "frame_time_epoch": "1583757057.813936138",
    "frame_time_relative": "62.307191989",
    "ip_dst": "192.168.0.1",
    "ip_dst_host": "192.168.0.1",
    "ip_len": "237",
    "ip_proto": "6",
    "ip_src": "192.168.1.1",
    "ip_src_host": "192.168.1.1",
    "ip_version": "4",
    "tcp_ack": "1",
    "tcp_dstport": "443",
    "tcp_flags": "0x00000018",
    "tcp_len": "197",
    "tcp_nxtseq": "198",
    "tcp_seq": "1",
    "tcp_srcport": "49907",
    "tls_handshake_extensions_server_name": "login.example.com"
  },
  "source": {
    "domain": "192.168.1.1",
    "ip": "192.168.1.1",
    "port": 49907
  }
},
...
]
```

### Required
* [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
* [github.com/elastic/go-elasticsearch for 7.x](https://github.com/elastic/go-elasticsearch)
* [github.com/adriansr/flowhash](https://github.com/adriansr/flowhash)

### Install/Build
1. cd $GOPATH/src
2. go get -u github.com/adriansr/flowhash
3. cd $GOPATH/src/github.com
4. mkdir elastic (if needed)
5. cd $GOPATH/src/github.com/elastic
6. git clone -b 7.x https://github.com/elastic/go-elasticsearch.git
7. cd $GOPATH/src/
8. git clone https://github.com/rhpenguin/tshark-filter.git
9. cd $GOPATH/src/tshark-filter/tshark-filter
10. go build

### Usage

```
> tshark-filter --config <config_yml_path> --pcap <pcap_file_path> --action <action_name> --output <output_name> --pretty true
```
When default_action and/or default_output are specified in a yaml config, --action and/or --output are not needed.

e.g. Stdout output (Filtering)
```
./tshark-filter --config ./default.yml --pcap http.pcapng --action filter --output stdout --pretty true
```

e.g. Stdout output (Aggregating packets as a single flow)
```
./tshark-filter --config ./default.yml --pcap http.pcapng --action agg --output stdout --pretty true
```
Filtering and/or aggregation rules can be configured in the yaml file.

e.g. Elasticsearch output
```
./tshark-filter --config ./default.yml --pcap http.pcapng --action filter --output elasticsearch
```
An Elasticsearch address(url) and auth info can be configured in the yaml file.

### Config file in yaml format

* Configurations are saved as a yaml file.
* Filtering and/or aggregation rules are defined.
* Output settings for Elasticsearch are also defined.

e.g. default.yml

```
#
# Fields names passed to tshark command as -T ek -e <args>.
#
pcap_extracted_fields:
  - http.host
  - http.request.method
  - http.request.uri
  - tls.handshake.extensions_server_name

#
# Match conditions for packet fields extracted by pcap_extracted_fields.
#
# The following settings mean "(http_request_method AND http_request_uri) OR tls_handshake_extensions_server_name", for example.
#
pcap_field_conditions:
  - http_request_method: 
      match: regex           # 'exact', 'case_ignore', 'exists' or 'regex'
      value: ["^P.*","^G.*"] # In case of multiple values, they are ORed.
    http_request_uri:
      match: exists
  - tls_handshake_extensions_server_name:
      match: exists
```

* [tshark command reference](https://www.wireshark.org/docs/man-pages/tshark.html)

See more [examples](https://github.com/rhpenguin/tshark-filter/tree/master/tshark-filter/examples) in tshark-filter/examples directory.
* http.yml : Filtering HTTP fields
* agg_by_community_id.yml : Packets are aggregated as a single flow by using community ID
* elasticsearch.yml : Exporting filtered and aggregated packets to Elasticsearch (by HTTP or Auth/HTTPS)
* download_winexe.yml : Filtering HTTP messages including MS EXE files by using Regex
* CVE_2020_0796.yml : Filtering example for CVE_2020_0796 (a.k.a CoronaBlue or SMBGhost)
* default.yml : Config template

### Filtering rules
* exact 
* case_ignore
* exists
* regex

### Aggregation
* By [Community ID Flow Hashing](https://github.com/corelight/community-id-spec)

