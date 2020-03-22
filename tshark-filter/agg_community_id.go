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

type aggCommunityID struct {
	config  *Config
	output  Output
	results map[string]map[string]interface{}
}

func (agg *aggCommunityID) Start() {

}

func (agg *aggCommunityID) PrintPacket(packet *map[string]interface{}) error {

	network := (*packet)["network"].(map[string]interface{})
	communityID := ""
	if v, ok := network["community_id"]; !ok {
		return nil
	} else {
		communityID = v.(string)
	}

	var result map[string]interface{}
	var ok bool
	if result, ok = agg.results[communityID]; !ok {
		result = *packet
	} else {
		if rnetwork, ok := result["network"].(map[string]interface{}); ok {
			if vn, ok := network["bytes"]; ok {
				if v, ok := rnetwork["bytes"]; ok {
					rnetwork["bytes"] = v.(uint64) + vn.(uint64)
					result["network"] = rnetwork
				}
			}
			if vn, ok := network["packets"]; ok {
				if v, ok := rnetwork["packets"]; ok {
					rnetwork["packets"] = v.(uint64) + vn.(uint64)
					result["network"] = rnetwork
				}
			}
		}
		packetData := (*packet)["packet"].(map[string]interface{})
		for pk, pv := range packetData {
			isTargetField := func() bool {
				for _, field := range agg.config.Agg.Fields {
					if field == pk {
						return true
					}
				}
				return false
			}
			if isTargetField() == true {
				mergeTargetField := func(pvOrg interface{}) {
					var pv string
					var ok bool
					if pv, ok = pvOrg.(string); !ok {
						return
					}
					rpacketData := result["packet"].(map[string]interface{})
					if v, ok := rpacketData[pk]; !ok {
						rpacketData[pk] = pv
					} else {
						var vals []string
						if v0, ok := v.(string); ok {
							vals = append(vals, v0)
						} else if v1, ok := v.([]string); ok {
							vals = append(vals, v1...)
						}
						var dup bool
						for _, v := range vals {
							if v == pv {
								dup = true
							}
						}
						if dup == false {
							var newPv []string
							if v0, ok := v.(string); ok {
								newPv = append(newPv, v0)
								newPv = append(newPv, pv)
							} else if v1, ok := v.([]string); ok {
								newPv = append(newPv, v1...)
								newPv = append(newPv, pv)
							}
							if len(newPv) > 0 {
								rpacketData[pk] = newPv
								result["packet"] = rpacketData
							}
						}
					}
				}
				mergeTargetField(pv)
			}
		}
	}
	agg.results[communityID] = result
	return nil
}

func (agg *aggCommunityID) End() {
	if len(agg.results) > 0 {
		agg.output.Start()
		for _, packet := range agg.results {
			err := agg.output.PrintPacket(&packet)
			if err != nil {
				break
			}
		}
		agg.output.End()
	}
}
