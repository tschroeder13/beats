// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package elasticsearch

import (
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/esleg/eslegclient"
	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/outputs/outil"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

func init() {
	outputs.RegisterType("elasticsearch", makeES)
}

const logSelector = "elasticsearch"

func makeES(
	im outputs.IndexManager,
	beat beat.Info,
	observer outputs.Observer,
	cfg *config.C,
) (outputs.Group, error) {
	log := logp.NewLogger(logSelector)
	if !cfg.HasField("bulk_max_size") {
		_ = cfg.SetInt("bulk_max_size", -1, defaultBulkSize)
	}

	index, pipeline, err := buildSelectors(im, beat, cfg)
	if err != nil {
		return outputs.Fail(err)
	}

	esConfig := defaultConfig
	if err := cfg.Unpack(&esConfig); err != nil {
		return outputs.Fail(err)
	}

	policy, err := newNonIndexablePolicy(esConfig.NonIndexablePolicy)
	if err != nil {
		log.Errorf("error while creating file identifier: %v", err)
		return outputs.Fail(err)
	}

	hosts, err := outputs.ReadHostList(cfg)
	if err != nil {
		return outputs.Fail(err)
	}

	if proxyURL := esConfig.Transport.Proxy.URL; proxyURL != nil && !esConfig.Transport.Proxy.Disable {
		log.Debugf("breaking down proxy URL. Scheme: '%s', host[:port]: '%s', path: '%s'", proxyURL.Scheme, proxyURL.Host, proxyURL.Path)
		log.Infof("Using proxy URL: %s", proxyURL)
	}

	params := esConfig.Params
	if len(params) == 0 {
		params = nil
	}

	if policy.action() == dead_letter_index {
		index = DeadLetterSelector{
			Selector:        index,
			DeadLetterIndex: policy.index(),
		}
	}

	clients := make([]outputs.NetworkClient, len(hosts))
	for i, host := range hosts {
		esURL, err := common.MakeURL(esConfig.Protocol, esConfig.Path, host, 9200)
		if err != nil {
			log.Errorf("Invalid host param set: %s, Error: %+v", host, err)
			return outputs.Fail(err)
		}

		var client outputs.NetworkClient
		client, err = NewClient(ClientSettings{
			ConnectionSettings: eslegclient.ConnectionSettings{
				URL:              esURL,
				Beatname:         beat.Beat,
				Kerberos:         esConfig.Kerberos,
				Username:         esConfig.Username,
				Password:         esConfig.Password,
				APIKey:           esConfig.APIKey,
				Parameters:       params,
				Headers:          esConfig.Headers,
				CompressionLevel: esConfig.CompressionLevel,
				Observer:         observer,
				EscapeHTML:       esConfig.EscapeHTML,
				Transport:        esConfig.Transport,
			},
			Index:              index,
			Pipeline:           pipeline,
			Observer:           observer,
			NonIndexableAction: policy.action(),
		}, &connectCallbackRegistry)
		if err != nil {
			return outputs.Fail(err)
		}

		client = outputs.WithBackoff(client, esConfig.Backoff.Init, esConfig.Backoff.Max)
		clients[i] = client
	}

	return outputs.SuccessNet(esConfig.Queue, esConfig.LoadBalance, esConfig.BulkMaxSize, esConfig.MaxRetries, clients)
}

func buildSelectors(
	im outputs.IndexManager,
	beat beat.Info,
	cfg *config.C,
) (index outputs.IndexSelector, pipeline *outil.Selector, err error) {
	index, err = im.BuildSelector(cfg)
	if err != nil {
		return index, pipeline, err
	}

	pipelineSel, err := buildPipelineSelector(cfg)
	if err != nil {
		return index, pipeline, err
	}

	if !pipelineSel.IsEmpty() {
		pipeline = &pipelineSel
	}

	return index, pipeline, err
}

func buildPipelineSelector(cfg *config.C) (outil.Selector, error) {
	return outil.BuildSelectorFromConfig(cfg, outil.Settings{
		Key:              "pipeline",
		MultiKey:         "pipelines",
		EnableSingleOnly: true,
		FailEmpty:        false,
		Case:             outil.SelectorLowerCase,
	})
}
