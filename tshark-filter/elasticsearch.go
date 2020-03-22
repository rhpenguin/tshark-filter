package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/elastic/go-elasticsearch"
	"github.com/elastic/go-elasticsearch/esapi"
)

type ElasticsearchOutput struct {
	config      *Config
	esIndex     string
	verbose     string
	client      *elasticsearch.Client
	packetJsons []map[string]interface{}
}

type BulkResponse struct {
	Errors bool `json:"errors"`
	Items  []struct {
		Index struct {
			ID     string `json:"_id"`
			Result string `json:"result"`
			Status int    `json:"status"`
			Error  struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
				Cause  struct {
					Type   string `json:"type"`
					Reason string `json:"reason"`
				} `json:"caused_by"`
			} `json:"error"`
		} `json:"index"`
	} `json:"items"`
}

func (es *ElasticsearchOutput) Init(config *Config, esIndex string, verbose string) error {
	if config.Elasticsearch.Address == "" {
		return errors.New("Elasticsearch address not specified")
	}
	es.config = config
	es.esIndex = esIndex
	es.verbose = verbose
	var err error
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 10 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       nil,
	}

	var urls []string
	urls = append(urls, es.config.Elasticsearch.Address)

	esConfig := elasticsearch.Config{
		Addresses: urls,
	}

	if es.config.Elasticsearch.UserName != "" {
		esConfig.Username = es.config.Elasticsearch.UserName
		esConfig.Password = es.config.Elasticsearch.Password
	}

	if es.config.Elasticsearch.SSLCaCertificate != "" {
		cert, err := ioutil.ReadFile(es.config.Elasticsearch.SSLCaCertificate)
		if err != nil {
			return err
		}
		esConfig.CACert = cert
	}

	if es.config.Elasticsearch.SSLVerificationDisabled == true {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	if verbose == "true" {
		fmt.Printf("elasticsearch.NewClient():\nesConfig:\n%#v\n", esConfig)
		fmt.Printf("elasticsearch.NewClient():\nCesConfig.CACert:\n%#v\n", string(esConfig.CACert))
		fmt.Printf("elasticsearch.NewClient():\ntransport:\n%#v\n", *transport)
	}

	es.client, err = elasticsearch.NewClient(esConfig)
	if err != nil {
		return err
	}

	return nil
}

func (es *ElasticsearchOutput) Start() {
}

func (es *ElasticsearchOutput) End() {
	if len(es.packetJsons) > 0 {
		err := es.bulkPut()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return
		}
	}
}

func (es *ElasticsearchOutput) bulkPut() error {
	var buf bytes.Buffer
	var response *esapi.Response
	var err error
	var raw map[string]interface{}
	var blk *BulkResponse

	for _, packetJson := range es.packetJsons {

		genIndex := func() string {
			if es.esIndex != "" {
				return es.esIndex
			}
			timestamp, _ := time.Parse(time.RFC3339, packetJson["@timestamp"].(string))
			esIndex := fmt.Sprintf("tshark-filter-%d-%02d-%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())
			return esIndex
		}

		genDocumentID := func() string {
			if es.config.Elasticsearch.DocumentID == "auto" {
				return ""
			} else if es.config.Elasticsearch.DocumentID == "community_id" {
				timestamp := ""
				if v, ok := packetJson["packet"]; !ok {
					return ""
				} else {
					if v, ok := v.(map[string]interface{}); ok {
						if v, ok := v["frame_time_epoch"]; !ok {
							return ""
						} else {
							timestamp = v.(string)
						}
					} else {
						return ""
					}
				}
				if v, ok := packetJson["network"]; ok {
					if v0, ok := v.(map[string]interface{}); ok {
						if v1, ok := v0["community_id"]; !ok {
							return ""
						} else {
							community_id := v1.(string)
							hash := sha256.New()
							hash.Write([]byte(timestamp))
							hash.Write([]byte(community_id))
							return fmt.Sprintf("%x", hash.Sum(nil))
						}
					}
				}
			}
			return ""
		}
		documentID := genDocumentID()

		var meta []byte
		if documentID == "" {
			meta = []byte(fmt.Sprintf(`{ "index" : { "_index" : "%s" } }%s`, genIndex(), "\n"))
		} else {
			meta = []byte(fmt.Sprintf(`{ "index" : { "_index" : "%s", "_id" : "%s" } }%s`, genIndex(), documentID, "\n"))
		}
		data, err := json.Marshal(packetJson)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return err
		}
		data = append(data, "\n"...)
		buf.Grow(len(meta) + len(data))
		buf.Write(meta)
		buf.Write(data)
		if es.verbose == "true" {
			fmt.Printf("meta:\n%s\n", string(meta))
			fmt.Printf("data:\n%s\n", string(data))
		}
	}

	response, err = es.client.Bulk(bytes.NewReader(buf.Bytes()))
	if es.verbose == "true" {
		fmt.Printf("Bulk response:\n%#v\n", response)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return err
	}
	if response.IsError() {
		if err := json.NewDecoder(response.Body).Decode(&raw); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return err
		} else {
			if es.verbose == "true" {
				fmt.Printf("Bulk response (raw):\n%#v\n", raw)
			}
			fmt.Fprintf(os.Stderr, "  Error: [%d] %s: %s\n",
				response.StatusCode,
				raw["error"].(map[string]interface{})["type"],
				raw["error"].(map[string]interface{})["reason"],
			)
		}
	} else {
		if err := json.NewDecoder(response.Body).Decode(&blk); err != nil {
			fmt.Fprintf(os.Stderr, "Failure to to parse response body: %s\n", err)
		} else {
			if es.verbose == "true" {
				fmt.Printf("Bulk response (blk):\n%#v\n", blk)
			}
			for _, d := range blk.Items {
				if d.Index.Status > 201 {
					fmt.Fprintf(os.Stderr, "  Error: [%d]: (ID: %s) %s: %s: %s: %s\n",
						d.Index.Status,
						d.Index.ID,
						d.Index.Error.Type,
						d.Index.Error.Reason,
						d.Index.Error.Cause.Type,
						d.Index.Error.Cause.Reason,
					)
				} else {
					if es.verbose == "true" {
						fmt.Printf("  OK: [%d]: (ID: %s)\n",
							d.Index.Status,
							d.Index.ID,
						)
					}
				}
			}
		}
	}

	response.Body.Close()
	buf.Reset()

	es.packetJsons = es.packetJsons[:0]
	return nil
}

func (es *ElasticsearchOutput) PrintPacket(packet *map[string]interface{}) error {
	es.packetJsons = append(es.packetJsons, *packet)
	if len(es.packetJsons) >= es.config.Elasticsearch.Bulk {
		err := es.bulkPut()
		if err != nil {
			return err
		}
	}
	return nil
}
