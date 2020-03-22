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
