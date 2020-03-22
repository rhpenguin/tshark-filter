//
// Copyright (C) 2019-2020 TETSUHARU HANADA <rhpenguine@gmail.com>
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/adriansr/flowhash"
)

type filterPacket struct {
	config     *Config
	output     Output
	prettyJson string
	pcapFile   string
	created    string
	verbose    string
	n          int
}

func (filter *filterPacket) setResult(layers, result *map[string]interface{}) {
	packet := make(map[string]interface{})
	for fkey, fval := range *layers {
		if fval0, ok := fval.(string); ok {
			packet[fkey] = fval0
		} else if fval1, ok := fval.([]interface{}); ok {
			if len(fval1) == 1 {
				packet[fkey] = fval1[0]
			} else if len(fval1) > 1 {
				packet[fkey] = fval1
			}
		}
	}
	if filter.config.MaxFieldLen > 0 {
		for k, v := range packet {
			if v, ok := v.(string); ok && len(v) > filter.config.MaxFieldLen {
				v = v[0:filter.config.MaxFieldLen]
				packet[k] = v
			}
		}
	}
	(*result)["packet"] = packet
}

func (filter *filterPacket) setECS(packet, layers, result *map[string]interface{}) {
	var err error
	srcIP := ""
	dstIP := ""
	srcPort := int64(0)
	dstPort := int64(0)
	protocol := int64(0)
	icmpType := int64(0)
	icmpCode := int64(0)
	networkType := "unknown"
	transport := ""
	srcHost := ""
	dstHost := ""

	if _, ok := (*layers)["ipv6_src"]; ok {
		srcIP = getPacketValue(layers, "ipv6_src")
		dstIP = getPacketValue(layers, "ipv6_dst")
		srcHost = getPacketValue(layers, "ipv6_src_host")
		dstHost = getPacketValue(layers, "ipv6_dst_host")
		networkType = "ipv6"
	} else if _, ok := (*layers)["ip_src"]; ok {
		srcIP = getPacketValue(layers, "ip_src")
		dstIP = getPacketValue(layers, "ip_dst")
		srcHost = getPacketValue(layers, "ip_src_host")
		dstHost = getPacketValue(layers, "ip_dst_host")
		networkType = "ipv4"
	}
	if _, ok := (*layers)["tcp_srcport"]; ok {
		protocol = 6
		transport = "tcp"
		portStr := getPacketValue(layers, "tcp_srcport")
		srcPort, err = strconv.ParseInt(portStr, 10, 64)
		if err == nil {
			portStr = getPacketValue(layers, "tcp_dstport")
			dstPort, err = strconv.ParseInt(portStr, 10, 64)
		}
	} else if _, ok := (*layers)["udp_srcport"]; ok {
		protocol = 17
		transport = "udp"
		portStr := getPacketValue(layers, "udp_srcport")
		srcPort, err = strconv.ParseInt(portStr, 10, 64)
		if err == nil {
			portStr = getPacketValue(layers, "udp_dstport")
			dstPort, err = strconv.ParseInt(portStr, 10, 64)
		}
	} else if _, ok := (*layers)["icmp_type"]; ok {
		protocol = 1
		transport = "icmp"
		icmpStr := getPacketValue(layers, "icmp_type")
		icmpType, err = strconv.ParseInt(icmpStr, 10, 64)
		if err == nil {
			icmpStr = getPacketValue(layers, "icmp_code")
			icmpCode, err = strconv.ParseInt(icmpStr, 10, 64)
		}
	} else if _, ok := (*layers)["icmpv6_type"]; ok {
		protocol = 58
		transport = "ipv6-icmp"
		icmpStr := getPacketValue(layers, "icmpv6_type")
		icmpType, err = strconv.ParseInt(icmpStr, 10, 64)
		if err == nil {
			icmpStr = getPacketValue(layers, "icmpv6_code")
			icmpCode, err = strconv.ParseInt(icmpStr, 10, 64)
		}
	} else {
		if networkType == "ipv4" {
			protoStr := getPacketValue(layers, "ip_proto")
			if protoStr != "" {
				protocol, _ = strconv.ParseInt(protoStr, 10, 64)
			}
		} else if networkType == "ipv6" {
			protoStr := getPacketValue(layers, "ipv6_nxt")
			if protoStr != "" {
				protocol, _ = strconv.ParseInt(protoStr, 10, 64)
			}
		}
	}

	network := make(map[string]interface{})
	source := make(map[string]interface{})
	destination := make(map[string]interface{})
	var relatedIPs []string
	event := map[string]interface{}{
		"module":  "pcap",
		"type":    "protocol",
		"created": filter.created,
	}
	agent := map[string]interface{}{
		"type": "tshark-filter",
	}
	file := map[string]interface{}{
		"name": filter.pcapFile,
	}

	if protocol != 0 {
		network["iana_number"] = strconv.FormatInt(protocol, 10)
	}
	if transport != "" {
		network["transport"] = transport
	}
	network["type"] = networkType

	if srcIP != "" {
		source["ip"] = srcIP
		relatedIPs = append(relatedIPs, srcIP)
	}
	if srcHost != "" {
		source["domain"] = srcHost
	}
	if srcPort != 0 {
		source["port"] = srcPort
	}
	if dstIP != "" {
		destination["ip"] = dstIP
		relatedIPs = append(relatedIPs, dstIP)
	}
	if dstHost != "" {
		destination["domain"] = dstHost
	}
	if dstPort != 0 {
		destination["port"] = dstPort
	}

	if srcIP != "" && dstIP != "" && protocol != 0 {
		flow := flowhash.Flow{}
		communityID := ""
		flow.SourceIP = net.ParseIP(srcIP)
		flow.DestinationIP = net.ParseIP(dstIP)
		flow.Protocol = uint8(protocol)
		if protocol == 6 || protocol == 17 {
			if srcPort != 0 && dstPort != 0 {
				flow.SourcePort = uint16(srcPort)
				flow.DestinationPort = uint16(dstPort)
				communityID = flowhash.CommunityID.Hash(flow)
			}
		} else if protocol == 1 || protocol == 58 {
			flow.ICMP.Type = uint8(icmpType)
			flow.ICMP.Code = uint8(icmpCode)
			communityID = flowhash.CommunityID.Hash(flow)
		}
		if communityID != "" {
			network["community_id"] = communityID
		}
	}

	if len(relatedIPs) > 0 {
		network["related"] = map[string]interface{}{
			"ip": relatedIPs,
		}
	}

	if _, ok := (*layers)["frame_len"]; ok {
		v := getPacketValue(layers, "frame_len")
		flen, err := strconv.ParseUint(v, 10, 64)
		if err == nil {
			network["bytes"] = flen
		}
	}
	network["packets"] = uint64(1)

	if _, ok := (*layers)["frame_protocols"]; ok {
		v := getPacketValue(layers, "frame_protocols")
		if v != "" {
			frameProtocols := strings.Split(v, ":")
			for i, frameProtocol := range frameProtocols {
				if frameProtocol == "tcp" || frameProtocol == "udp" {
					if i+2 <= len(frameProtocols) {
						network["protocol"] = frameProtocols[i+1]
					}
					break
				} else if frameProtocol == "ip" || frameProtocol == "ipv6" {
					if i+2 <= len(frameProtocols) {
						upper := frameProtocols[i+1]
						if upper != "tcp" && upper != "udp" {
							network["protocol"] = upper
							break
						}
					}
				} else if i == len(frameProtocols)-1 {
					network["protocol"] = frameProtocol
				}
			}
		}
	}

	(*result)["network"] = network
	(*result)["source"] = source
	(*result)["destination"] = destination
	(*result)["event"] = event
	(*result)["agent"] = agent
	(*result)["file"] = file
}

func (filter *filterPacket) Exec(index, packet map[string]interface{}, ctx interface{}) error {
	if filter.verbose == "true" {
		fmt.Println("filter.Exec: packet\n", packet)
	}
	result := make(map[string]interface{})
	var layers map[string]interface{}
	if v0, ok := packet["layers"]; !ok {
		return nil
	} else {
		if layers, ok = v0.(map[string]interface{}); !ok {
			return nil
		}
	}
	found := false
	for _, condition := range filter.config.Conditions {
		matched := int(0)
		for ck, cv0 := range condition {
			if v0, ok := layers[ck]; ok {
				match := func(v string, cv interface{}) bool {
					if cv1, ok := cv.(string); ok {
						if v == cv1 {
							return true
						}
					} else if cv1, ok := cv.(int); ok {
						if v == strconv.FormatInt(int64(cv1), 10) {
							return true
						}
					} else if cv1, ok := cv.([]interface{}); ok {
						for _, cv2 := range cv1 {
							if cv3, ok := cv2.(string); ok {
								if v == cv3 {
									return true
								}
							} else if cv3, ok := cv2.(int); ok {
								if v == strconv.FormatInt(int64(cv3), 10) {
									return true
								}
							}
						}
					} else if cv1, ok := cv.(map[interface{}]interface{}); ok {
						if how, ok := cv1["match"]; ok {
							switch how {
							case "regex":
								var regexes []*regexp.Regexp
								if r, ok := cv1["regex"]; ok {
									regexes = r.([]*regexp.Regexp)
								} else {
									if cmpValue0, ok := cv1["value"]; ok {
										if cmpValue1, ok := cmpValue0.(string); ok {
											regex, err := regexp.Compile(cmpValue1)
											if err == nil {
												regexes = append(regexes, regex)
											} else {
												fmt.Fprintf(os.Stderr, "%s, %s\n", err, cmpValue1)
											}
											cv1["regex"] = regexes
										} else if cmpValues1, ok := cmpValue0.([]interface{}); ok {
											for _, cv2 := range cmpValues1 {
												if cv3, ok := cv2.(string); ok {
													regex, err := regexp.Compile(cv3)
													if err == nil {
														regexes = append(regexes, regex)
													} else {
														fmt.Fprintf(os.Stderr, "%s, %s\n", err, cmpValue1)
													}
												}
											}
											cv1["regex"] = regexes
										}
									}
								}
								if regexes == nil || len(regexes) < 1 {
									return false
								}
								for _, regex := range regexes {
									if regex.MatchString(v) == true {
										return true
									}
								}
							case "exact", "case_ignore":
								if cmpValue0, ok := cv1["value"]; ok {
									if cmpValue1, ok := cmpValue0.(string); ok {
										if (how == "case_ignore" && strings.ToLower(cmpValue1) == strings.ToLower(v)) ||
											cmpValue1 == v {
											return true
										}
									} else if cmpValue1, ok := cmpValue0.(int); ok {
										if v == strconv.FormatInt(int64(cmpValue1), 10) {
											return true
										}
									} else if cmpValue1, ok := cmpValue0.([]interface{}); ok {
										for _, cv2 := range cmpValue1 {
											if cv3, ok := cv2.(string); ok {
												if (how == "case_ignore" && strings.ToLower(v) == strings.ToLower(cv3)) ||
													v == cv3 {
													return true
												}
											} else if cv3, ok := cv2.(int); ok {
												if v == strconv.FormatInt(int64(cv3), 10) {
													return true
												}
											}
										}
									}
								}
							case "exists":
								return true
							default:
							}
						}
					}
					return false
				}
				if v1, ok := v0.(string); ok {
					if match(v1, cv0) == false {
						break
					}
					matched++
				} else if v1, ok := v0.([]interface{}); ok {
					for _, v2 := range v1 {
						if v2, ok := v2.(string); ok {
							if match(v2, cv0) == false {
								break
							}
							matched++
						}
					}
				} else {
					break
				}
			}
		}
		if matched == len(condition) {
			found = true
			break
		}
	}
	if found == false {
		return nil
	}

	if timestamp, ok := packet["timestamp"]; ok {
		if timestamp, ok := timestamp.(string); ok {
			t, err := strconv.ParseInt(timestamp, 10, 64)
			if err == nil {
				sec := t / 1000
				msec := (t - (sec * 1000))
				t2 := time.Unix(sec, 0)
				timestamp = t2.UTC().Format("2006-01-02T15:04:05")
				timestamp += "." + fmt.Sprintf("%03d", msec) + "Z"
				result["@timestamp"] = timestamp
				delete(packet, "timestamp")
			}
		}
	} else {
		timestamp = time.Now().UTC().Format("2006-01-02T15:04:05") + ".000Z"
		result["@timestamp"] = timestamp
	}

	filter.setECS(&packet, &layers, &result)
	filter.setResult(&layers, &result)

	if filter.n == 0 {
		filter.output.Start()
	}
	err := filter.output.PrintPacket(&result)
	if err != nil {
		return err
	}
	filter.n++
	return nil
}

func (filter *filterPacket) End(ctx interface{}) {
	if filter.n > 0 {
		filter.output.End()
	}
}
