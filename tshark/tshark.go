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
package tshark

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type TsharkConfig struct {
	ExePath string
	Args    []string
	Verbose string
}

type Tshark struct {
	config TsharkConfig
	filter struct {
		start   func(ctx interface{})
		exec    func(indexJson, packetJson map[string]interface{}, ctx interface{}) (bool, error)
		end     func(ctx interface{}, results *[]map[string]interface{})
		ctx     interface{}
		counter int
	}
	put struct {
		start   func(ctx interface{})
		exec    func(indexJson, packetJson map[string]interface{}, ctx interface{}) error
		end     func(ctx interface{})
		ctx     interface{}
		counter int
	}
	unreadBuf       []byte
	unreadIndexJson map[string]interface{}
	results         *[]map[string]interface{}
}

func New(config *TsharkConfig) *Tshark {
	var tsk Tshark
	if config != nil {
		tsk.config = *config
	}
	if tsk.config.ExePath == "" {
		tsk.config.ExePath = "/usr/bin/tshark"
	}
	return &tsk
}

func (tsk *Tshark) Write(data []byte) (int, error) {
	dlen := len(tsk.unreadBuf) + len(data)
	text := ""
	if len(tsk.unreadBuf) > 0 {
		text += string(tsk.unreadBuf)
	}
	text += string(data)
	hpos := int(0)
	pos := int(0)
	nl := int(0)
	var c rune
	for pos, c = range text {
		if c == '\n' {
			nl++
			line := []byte(text[hpos:pos])
			pos++
			hpos = pos
			var jsonData interface{}
			err := json.Unmarshal(line, &jsonData)
			if err == nil {
				if tsk.unreadIndexJson == nil {
					tsk.unreadIndexJson = jsonData.(map[string]interface{})
				} else {
					packetJson := jsonData.(map[string]interface{})
					if tsk.filter.exec != nil {
						if tsk.filter.counter == 0 && tsk.filter.start != nil {
							tsk.filter.start(tsk.filter.ctx)
						}
						tsk.filter.counter++
						flag, err := tsk.filter.exec(tsk.unreadIndexJson, packetJson, tsk.filter.ctx)
						if err != nil {
							return len(data), err
						}
						if flag == true {
							result := map[string]interface{}{
								"index":  tsk.unreadIndexJson,
								"packet": packetJson,
							}
							*(tsk.results) = append(*(tsk.results), result)
						}
					} else if tsk.put.exec != nil {
						if tsk.put.counter == 0 && tsk.put.start != nil {
							tsk.put.start(tsk.filter.ctx)
						}
						tsk.put.counter++
						err := tsk.put.exec(tsk.unreadIndexJson, packetJson, tsk.put.ctx)
						if err != nil {
							return len(data), err
						}
					}
					tsk.unreadIndexJson = nil
				}
			}
		}
	}
	if nl == 0 {
		tsk.unreadBuf = append(tsk.unreadBuf, data...)
	} else {
		if hpos >= dlen {
			tsk.unreadBuf = nil
		} else {
			tsk.unreadBuf = []byte(text[hpos:])
		}
	}
	return len(data), nil
}

func (tsk *Tshark) FilterImpl(pcapName string, fields *[]string,
	start func(ctx interface{}),
	filter func(indexJson, packetJson map[string]interface{}, ctx interface{}) (bool, error),
	end func(ctx interface{}, results *[]map[string]interface{}),
	ctx interface{}) ([]map[string]interface{}, error) {
	defer func() {
		if tsk.filter.counter > 0 && tsk.filter.exec != nil && tsk.filter.end != nil {
			tsk.filter.end(tsk.filter.ctx, tsk.results)
		}
		tsk.filter.start = nil
		tsk.filter.exec = nil
		tsk.filter.end = nil
		tsk.filter.ctx = nil
		tsk.results = nil
		tsk.filter.counter = 0
	}()
	var results []map[string]interface{}
	var args []string
	args = append(args, "-r")
	args = append(args, pcapName)
	args = append(args, "-T")
	args = append(args, "ek")
	if fields != nil {
		for _, field := range *fields {
			args = append(args, "-e")
			args = append(args, field)
		}
	}
	if len(tsk.config.Args) > 0 {
		for _, arg := range tsk.config.Args {
			args = append(args, arg)
		}
	}

	if tsk.config.Verbose == "true" {
		fmt.Println("ExePath: ", tsk.config.ExePath)
		fmt.Println("args: ", args)
	}
	cmd := exec.Command(tsk.config.ExePath, args...)

	tsk.filter.start = start
	tsk.filter.exec = filter
	tsk.filter.end = end
	tsk.filter.ctx = ctx
	tsk.results = &results
	cmd.Stdout = tsk
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return results, err
	}

	return results, nil
}

func (tsk *Tshark) Filter(pcapName string, fields *[]string,
	filter func(indexJson, packetJson map[string]interface{}, ctx interface{}) (bool, error),
	ctx interface{}) ([]map[string]interface{}, error) {
	return tsk.FilterImpl(pcapName, fields, nil, filter, nil, ctx)
}

func (tsk *Tshark) LoadImpl(pcapName string, fields *[]string,
	start func(ctx interface{}),
	put func(indexJson, packetJson map[string]interface{}, ctx interface{}) error,
	end func(ctx interface{}),
	ctx interface{}) error {
	defer func() {
		if tsk.put.counter > 0 && tsk.put.exec != nil && tsk.put.end != nil {
			tsk.put.end(tsk.put.ctx)
		}
		tsk.put.start = nil
		tsk.put.exec = nil
		tsk.put.end = nil
		tsk.put.ctx = nil
		tsk.put.counter = 0
	}()
	var args []string
	args = append(args, "-r")
	args = append(args, pcapName)
	args = append(args, "-T")
	args = append(args, "ek")
	if fields != nil {
		for _, field := range *fields {
			args = append(args, "-e")
			args = append(args, field)
		}
	}

	if tsk.config.Verbose == "true" {
		fmt.Println("ExePath: ", tsk.config.ExePath)
		fmt.Println("args: ", args)
	}
	cmd := exec.Command(tsk.config.ExePath, args...)

	tsk.put.start = start
	tsk.put.exec = put
	tsk.put.end = end
	tsk.put.ctx = ctx
	cmd.Stdout = tsk
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func (tsk *Tshark) Load(pcapName string, fields *[]string,
	put func(indexJson, packetJson map[string]interface{}, ctx interface{}) error,
	ctx interface{}) error {
	return tsk.LoadImpl(pcapName, fields, nil, put, nil, ctx)
}
