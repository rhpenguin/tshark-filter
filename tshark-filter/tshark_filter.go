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
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"
	"tshark-filter/tshark"

	"gopkg.in/yaml.v2"
)

const Version string = "0.1"

type Output interface {
	Start()
	PrintPacket(packet *map[string]interface{}) error
	End()
}

type Config struct {
	Fields      []string                 `yaml:"pcap_extracted_fields"`
	Conditions  []map[string]interface{} `yaml:"pcap_field_conditions"` // match: 'regex', 'exact', 'case_ignore' or 'exists'
	Action      string                   `yaml:"default_action"`        // 'filter' or 'agg'
	MaxFieldLen int                      `yaml:"max_field_len"`
	Agg         struct {
		Type   string   `yaml:"type"` // 'community_id' or 'tcp'
		Fields []string `yaml:"extracted_result_fields"`
	} `yaml:"agg"`
	Output        string `yaml:"default_output"` // 'stdout' or 'elasticsearch'
	Elasticsearch struct {
		Address                 string `yaml:"address,omitempty"`
		UserName                string `yaml:"user_name,omitempty"`
		Password                string `yaml:"password,omitempty"`
		SSLVerificationDisabled bool   `yaml:"ssl_verification_disabled,omitempty"`
		SSLCaCertificate        string `yaml:"ssl_ca_certificate,omitempty"`
		DocumentID              string `yaml:"document_id,omitempty"`
		Bulk                    int    `yaml:"bulk,omitempty"`
	} `yaml:"elasticsearch"`
	Tshark struct {
		Exe  string   `yaml:"exe"`
		Args []string `yaml:"args"`
	}
}

var defFields = map[string]bool{
	"frame.interface_name": true,
	"frame.time_epoch":     true,
	"frame.time_delta":     true,
	"frame.time_relative":  true,
	"frame.number":         true,
	"frame.len":            true,
	"frame.protocols":      true,
	"ip.version":           true,
	"ip.len":               true,
	"ip.proto":             true,
	"ip.src":               true,
	"ip.src_host":          true,
	"ip.dst":               true,
	"ip.dst_host":          true,
	"ipv6.version":         true,
	"ipv6.plen":            true,
	"ipv6.nxt":             true,
	"ipv6.src":             true,
	"ipv6.src_host":        true,
	"ipv6.dst":             true,
	"ipv6.dst_host":        true,
	"udp.srcport":          true,
	"udp.dstport":          true,
	"udp.length":           true,
	"tcp.srcport":          true,
	"tcp.dstport":          true,
	"tcp.len":              true,
	"tcp.seq":              true,
	"tcp.nxtseq":           true,
	"tcp.ack":              true,
	"tcp.flags":            true,
	"icmp.type":            true,
	"icmp.code":            true,
	"icmpv6.type":          true,
	"icmpv6.code":          true,
}

func readConfig(confPath, verbose string) (Config, error) {
	var config Config
	buf, err := ioutil.ReadFile(confPath)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(buf, &config)
	if err != nil {
		return config, err
	}
	if config.Elasticsearch.Bulk == 0 {
		config.Elasticsearch.Bulk = 32
	}
	if verbose == "true" {
		fmt.Printf("readConfig: %#v\n", config)
	}
	return config, nil
}

func getPacketValue(layers *map[string]interface{}, key string) string {
	result := ""
	if v, ok := (*layers)[key]; ok {
		if result, ok = v.(string); ok {
		} else if v, ok := v.([]interface{}); ok && len(v) > 0 {
			if result, ok = v[0].(string); ok {
			}
		}
	}
	return result
}

func main() {
	if flag.Arg(0) == "version" {
		fmt.Printf("tshark_filter v%s\n", Version)
		return
	}
	action := flag.String("action", "", "Specify filter action (filter or agg)")
	confPath := flag.String("config", "default.yml", "Specify config filename")
	pcapFile := flag.String("pcap", "", "Specify pcap filename")
	outputMode := flag.String("output", "", "Specify output mode (stdout or elasticsearch)")
	prettyJson := flag.String("pretty", "false", "Specify pretty JSON (true or false)")
	esIndex := flag.String("es_index", "", "Specify Elasticsearch index")
	verbose := flag.String("verbose", "", "true or false")
	flag.Parse()
	if *pcapFile == "" {
		fmt.Printf("No pcap specified\n")
		return
	}
	if *confPath == "" {
		fmt.Printf("No config filename specified\n")
		return
	}
	config, err := readConfig(*confPath, *verbose)
	if err != nil {
		fmt.Printf("Failed to read config (%s)\n", err)
		return
	}
	if *action == "" {
		if config.Action != "" {
			*action = config.Action
		} else {
			*action = "filter"
		}
	}
	if *outputMode == "" {
		if config.Output != "" {
			*outputMode = config.Output
		} else {
			*outputMode = "stdout"
		}
	}

	var tconfig tshark.TsharkConfig
	tconfig.ExePath = config.Tshark.Exe
	tconfig.Verbose = *verbose
	tsk := tshark.New(&tconfig)

	var fields []string
	if len(config.Fields) > 0 {
		for _, cfgField := range config.Fields {
			if v, ok := defFields[cfgField]; ok && v == true {
				defFields[cfgField] = false
			}
			fields = append(fields, cfgField)
		}
	}
	for defField, v := range defFields {
		if v == true {
			fields = append(fields, defField)
		}
	}

	var output Output
	if *outputMode == "stdout" {
		stdoutOutput := StdOutput{
			prettyJson: *prettyJson,
		}
		output = &stdoutOutput
	} else if *outputMode == "elasticsearch" {
		esOutput := ElasticsearchOutput{}
		err := esOutput.Init(&config, *esIndex, *verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return
		}
		output = &esOutput
	} else {
		fmt.Printf("Unknown output specified: %s\n", *outputMode)
		return
	}

	if *action == "filter" || *action == "agg" {
		filterPacket := filterPacket{
			config:     &config,
			prettyJson: *prettyJson,
			pcapFile:   *pcapFile,
			verbose:    *verbose,
			created:    time.Now().UTC().Format("2006-01-02T15:04:05") + ".000Z",
		}
		if *action == "agg" {
			if config.Agg.Type == "community_id" {
				aggOutput := aggCommunityID{
					config:  filterPacket.config,
					output:  output,
					results: make(map[string]map[string]interface{}),
				}
				filterPacket.output = &aggOutput
			} else {
				fmt.Fprintf(os.Stderr, "%s\n", "Unknown agg_type")
				return
			}
		} else {
			filterPacket.output = output
		}
		err = tsk.LoadImpl(*pcapFile, &fields, nil, filterPacket.Exec, filterPacket.End, &filterPacket)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tshark command failed: %s\n", err)
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", "Unknown filter action")
		return
	}
}
