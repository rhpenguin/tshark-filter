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
	"encoding/json"
	"fmt"
	"os"
)

type StdOutput struct {
	prettyJson string
	n          int
}

func (so *StdOutput) Start() {
}

func (so *StdOutput) End() {
	if so.n > 0 {
		if so.prettyJson == "true" {
			fmt.Println("")
		}
		fmt.Println("]")
	}
}

func (so *StdOutput) PrintPacket(packet *map[string]interface{}) error {
	if so.n == 0 {
		if so.prettyJson == "true" {
			fmt.Println("[")
		} else {
			fmt.Print("[")
		}
	} else {
		fmt.Println(",")
	}
	var err error
	var jsonPacket []byte
	if so.prettyJson == "true" {
		jsonPacket, err = json.MarshalIndent(packet, "", "  ")
	} else {
		jsonPacket, err = json.Marshal(packet)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return nil
	}
	fmt.Print(string(jsonPacket))
	so.n++
	return nil
}
