// Copyright 2022 The prometheus-operator Authors
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

package validation

import (
	"encoding/json"
	"fmt"
	monitoringv1beta1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1beta1"
	"net"
	"strings"

	"errors"

	monitoringv1alpha1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1alpha1"
	"github.com/prometheus/alertmanager/config"
	"regexp"
)

type v1x1AlertmanagerConfig struct {
	alpha *monitoringv1alpha1.AlertmanagerConfig
	beta  *monitoringv1beta1.AlertmanagerConfig
}

var durationRe = regexp.MustCompile(`^(([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?$`)

// ValidateURL against the config.URL
// This could potentially become a regex and be validated via OpenAPI
// but right now, since we know we need to unmarshal into an upstream type
// after conversion, we validate we don't error when doing so
func ValidateURL(url string) (*config.URL, error) {
	var u config.URL
	err := json.Unmarshal([]byte(fmt.Sprintf(`"%s"`, url)), &u)
	if err != nil {
		return nil, fmt.Errorf("validate url from string failed for %s: %w", url, err)
	}
	return &u, nil
}

// ValidateAlertmanagerConfig checks that the given resource complies with the
// semantics of the Alertmanager configuration.
// In particular, it verifies things that can't be modelized with the OpenAPI
// specification such as routes should refer to an existing receiver.
func ValidateAlertmanagerConfig(amcRaw interface{}) error {
	var amcv1x1 v1x1AlertmanagerConfig
	switch amc := amcRaw.(type) {
	case *monitoringv1alpha1.AlertmanagerConfig:
		amcv1x1.alpha = amc
	case *monitoringv1beta1.AlertmanagerConfig:
		amcv1x1.beta = amc
	default:
		panic(fmt.Sprintf("unexpected type %T", amcRaw))
	}

	resolved, err := resolve(amcv1x1, []string{"Spec", "Receivers"})
	if err != nil {
		return err
	}
	recievers, err := validateReceivers(resolved)
	if err != nil {
		return err
	}

	var field string
	if amcv1x1.alpha != nil {
		field = "MuteTimeIntervals"
	} else if amcv1x1.beta != nil {
		field = "TimeIntervals"
	}
	resolved, err = resolve(amcv1x1, []string{"Spec", "Route", field})
	if err != nil {
		return err
	}
	intervals, err := validateIntervals(resolved)
	if err != nil {
		return err
	}

	resolved, err = resolve(amcv1x1, []string{"Spec", "Route"})
	if err != nil {
		return err
	}
	return validateAlertManagerRoutes(resolved, recievers, intervals, true)
}

func validateReceivers(receivers []interface{}) (map[string]struct{}, error) {

	var err error
	receiverNames := make(map[string]struct{})

	for _, receiver := range receivers {
		resolvedName, err := resolve(receiver, []string{"Name"})
		if err != nil {
			return nil, err
		}
		receiverName := resolvedName.(string)

		if _, found := receiverNames[receiverName]; found {
			return nil, fmt.Errorf("%q receiver is not unique: %w", receiverName, err)
		}
		receiverNames[receiverName] = struct{}{}

		resolvedPagerDutyConfigs, err := resolveList(receiver, []string{"PagerDutyConfigs"})
		if err != nil {
			return nil, err
		}
		if err = validatePagerDutyConfigs(resolvedPagerDutyConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'pagerDutyConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedOpsGenieConfigs, err := resolveList(receiver, []string{"OpsGenieConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateOpsGenieConfigs(resolvedOpsGenieConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'opsGenieConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedSlackConfigs, err := resolveList(receiver, []string{"SlackConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateSlackConfigs(resolvedSlackConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'slackConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedWebhookConfigs, err := resolveList(receiver, []string{"WebhookConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateWebhookConfigs(resolvedWebhookConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'webhookConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedWechatConfigs, err := resolveList(receiver, []string{"WeChatConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateWechatConfigs(resolvedWechatConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'weChatConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedEmailConfigs, err := resolveList(receiver, []string{"EmailConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateEmailConfig(resolvedEmailConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'emailConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedVictorOpsConfigs, err := resolveList(receiver, []string{"VictorOpsConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateVictorOpsConfigs(resolvedVictorOpsConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'victorOpsConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedPushoverConfigs, err := resolveList(receiver, []string{"PushoverConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validatePushoverConfigs(resolvedPushoverConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'pushOverConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedSnsConfigs, err := resolveList(receiver, []string{"SNSConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateSnsConfigs(resolvedSnsConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'snsConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedTelegramConfigs, err := resolveList(receiver, []string{"TelegramConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateTelegramConfigs(resolvedTelegramConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'telegramConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedWebexConfigs, err := resolveList(receiver, []string{"WebexConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateWebexConfigs(resolvedWebexConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'webexConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedDiscordConfigs, err := resolveList(receiver, []string{"DiscordConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateDiscordConfigs(resolvedDiscordConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'discordConfig' - receiver %s: %w", receiverName, err)
		}

		resolvedMSTeamsConfigs, err := resolveList(receiver, []string{"MSTeamsConfigs"})
		if err != nil {
			return nil, err
		}
		if err := validateMSTeamsConfigs(resolvedMSTeamsConfigs); err != nil {
			return nil, fmt.Errorf("failed to validate 'msteamsConfig' - receiver %s: %w", receiverName, err)
		}
	}

	return receiverNames, nil
}

func validatePagerDutyConfigs(configs []interface{}) error {
	for _, conf := range configs {
		resolvedURL, err := resolve(conf, []string{"URL"})
		if err != nil {
			return err
		}
		receiverURL := resolvedURL.(string)
		if receiverURL != "" {
			if _, err := ValidateURL(receiverURL); err != nil {
				return fmt.Errorf("pagerduty validation failed for 'url': %w", err)
			}
		}
		resolvedRoutingKey, err := resolve(conf, []string{"RoutingKey"})
		if err != nil {
			return err
		}
		resolvedServiceKey, err := resolve(conf, []string{"ServiceKey"})
		if err != nil {
			return err
		}
		if resolvedRoutingKey == nil && resolvedServiceKey == nil {
			return errors.New("one of 'routingKey' or 'serviceKey' is required")
		}

		var validator func() error
		if isAlpha() {
			validator = conf.(monitoringv1alpha1.PagerDutyConfig).HTTPConfig.Validate
		} else {
			validator = conf.(monitoringv1beta1.PagerDutyConfig).HTTPConfig.Validate
		}
		if err := validator(); err != nil {
			return err
		}
	}
	return nil
}

func validateOpsGenieConfigs(configs []interface{}) error {
	for _, config := range configs {
		if isAlpha() {
			opsGenieConfig := config.(monitoringv1alpha1.OpsGenieConfig)
			if err := opsGenieConfig.Validate(); err != nil {
				return err
			}
		} else {
			opsGenieConfig := config.(monitoringv1beta1.OpsGenieConfig)
			if err := opsGenieConfig.Validate(); err != nil {
				return err
			}
		}

		resolvedAPIURL, err := resolve(config, []string{"APIURL"})
		if err != nil {
			return err
		}
		configAPIURL := resolvedAPIURL.(string)
		if configAPIURL != "" {
			if _, err := ValidateURL(configAPIURL); err != nil {
				return fmt.Errorf("invalid 'apiURL': %w", err)
			}
		}

		var validator func() error
		if isAlpha() {
			validator = config.(monitoringv1alpha1.PagerDutyConfig).HTTPConfig.Validate
		} else {
			validator = config.(monitoringv1beta1.PagerDutyConfig).HTTPConfig.Validate
		}
		if err := validator(); err != nil {
			return err
		}
	}
	return nil
}

func validateDiscordConfigs(configs []interface{}) error {
	for _, config := range configs {
		var validator func() error
		if isAlpha() {
			if err := config.(monitoringv1alpha1.DiscordConfig).HTTPConfig.Validate(); err != nil {
				return err
			}
		} else {
			if err := config.(monitoringv1beta1.DiscordConfig).HTTPConfig.Validate(); err != nil {
				return err
			}
		}
		if err := validator(); err != nil {
			return err
		}
	}
	return nil
}

func validateSlackConfigs(configs []interface{}) error {
	for _, config := range configs {
		if isAlpha() {
			slackConfig := config.(monitoringv1alpha1.SlackConfig)
			if err := slackConfig.Validate(); err != nil {
				return err
			}

			if err := slackConfig.HTTPConfig.Validate(); err != nil {
				return err
			}
		} else {
			slackConfig := config.(monitoringv1beta1.SlackConfig)
			if err := slackConfig.Validate(); err != nil {
				return err
			}

			if err := slackConfig.HTTPConfig.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateWebhookConfigs(configs []interface{}) error {
	for _, config := range configs {
		resolvedURL, err := resolve(config, []string{"URL"})
		if err != nil {
			return err
		}
		resolvedURLSecret, err := resolve(config, []string{"URLSecret"})
		if err != nil {
			return err
		}
		if resolvedURL == nil && resolvedURLSecret == nil {
			return errors.New("one of 'url' or 'urlSecret' must be specified")
		}
		if resolvedURL != nil {
			if _, err := ValidateURL(*resolvedURL); err != nil {
				return fmt.Errorf("invalid 'url': %w", err)
			}
		}

		if err := config.HTTPConfig.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateWechatConfigs(configs []monitoringv1alpha1.WeChatConfig) error {
	for _, config := range configs {
		if config.APIURL != "" {
			if _, err := ValidateURL(config.APIURL); err != nil {
				return fmt.Errorf("invalid 'apiURL': %w", err)
			}
		}

		if err := config.HTTPConfig.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateEmailConfig(configs []monitoringv1alpha1.EmailConfig) error {
	for _, config := range configs {
		if config.To == "" {
			return errors.New("missing 'to' address")
		}

		if config.Smarthost != "" {
			_, _, err := net.SplitHostPort(config.Smarthost)
			if err != nil {
				return fmt.Errorf("invalid 'smarthost' %s: %w", config.Smarthost, err)
			}
		}

		if config.Headers != nil {
			// Header names are case-insensitive, check for collisions.
			normalizedHeaders := map[string]struct{}{}
			for _, v := range config.Headers {
				normalized := strings.ToLower(v.Key)
				if _, ok := normalizedHeaders[normalized]; ok {
					return fmt.Errorf("duplicate header %q", normalized)
				}
				normalizedHeaders[normalized] = struct{}{}
			}
		}
	}
	return nil
}

func validateVictorOpsConfigs(configs []monitoringv1alpha1.VictorOpsConfig) error {
	for _, config := range configs {

		// from https://github.com/prometheus/alertmanager/blob/a7f9fdadbecbb7e692d2cd8d3334e3d6de1602e1/config/notifiers.go#L497
		reservedFields := map[string]struct{}{
			"routing_key":         {},
			"message_type":        {},
			"state_message":       {},
			"entity_display_name": {},
			"monitoring_tool":     {},
			"entity_id":           {},
			"entity_state":        {},
		}

		if len(config.CustomFields) > 0 {
			for _, v := range config.CustomFields {
				if _, ok := reservedFields[v.Key]; ok {
					return fmt.Errorf("usage of reserved word %q is not allowed in custom fields", v.Key)
				}
			}
		}

		if config.RoutingKey == "" {
			return errors.New("missing 'routingKey' key")
		}

		if config.APIURL != "" {
			if _, err := ValidateURL(config.APIURL); err != nil {
				return fmt.Errorf("'apiURL' %s invalid: %w", config.APIURL, err)
			}
		}

		if err := config.HTTPConfig.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validatePushoverConfigs(configs []monitoringv1alpha1.PushoverConfig) error {
	for _, config := range configs {
		if config.UserKey == nil && config.UserKeyFile == nil {
			return fmt.Errorf("one of userKey or userKeyFile must be configured")
		}

		if config.Token == nil && config.TokenFile == nil {
			return fmt.Errorf("one of token or tokenFile must be configured")
		}

		if err := config.HTTPConfig.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func validateSnsConfigs(configs []monitoringv1alpha1.SNSConfig) error {
	for _, config := range configs {
		if (config.TargetARN == "") != (config.TopicARN == "") != (config.PhoneNumber == "") {
			return fmt.Errorf("must provide either a Target ARN, Topic ARN, or Phone Number for SNS config")
		}

		if err := config.HTTPConfig.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateTelegramConfigs(configs []monitoringv1alpha1.TelegramConfig) error {
	for _, config := range configs {

		if config.BotToken == nil && config.BotTokenFile == nil {
			return fmt.Errorf("mandatory field botToken or botTokenfile is empty")
		}

		if config.ChatID == 0 {
			return fmt.Errorf("mandatory field %q is empty", "chatID")
		}

		if err := config.HTTPConfig.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func validateWebexConfigs(configs []monitoringv1alpha1.WebexConfig) error {
	for _, config := range configs {
		if *config.APIURL != "" {
			if _, err := ValidateURL(string(*config.APIURL)); err != nil {
				return fmt.Errorf("invalid 'apiURL': %w", err)
			}
		}

		if err := config.HTTPConfig.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func validateMSTeamsConfigs(configs []monitoringv1alpha1.MSTeamsConfig) error {
	for _, config := range configs {
		if err := config.HTTPConfig.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// validateAlertManagerRoutes verifies that the given route and all its children are semantically valid.
// because of the self-referential issues mentioned in https://github.com/kubernetes/kubernetes/issues/62872
// it is not currently possible to apply OpenAPI validation to a v1alpha1.Route
func validateAlertManagerRoutes(r *monitoringv1alpha1.Route, receivers, muteTimeIntervals map[string]struct{}, topLevelRoute bool) error {
	if r == nil {
		return nil
	}

	if r.Receiver == "" {
		if topLevelRoute {
			return errors.New("root route must define a receiver")
		}
	} else {
		if _, found := receivers[r.Receiver]; !found {
			return fmt.Errorf("receiver %q not found", r.Receiver)
		}
	}

	if groupLen := len(r.GroupBy); groupLen > 0 {
		groupedBy := make(map[string]struct{}, groupLen)
		for _, str := range r.GroupBy {
			if _, found := groupedBy[str]; found {
				return fmt.Errorf("duplicate values not permitted in route 'groupBy': %v", r.GroupBy)
			}
			groupedBy[str] = struct{}{}
		}
		if _, found := groupedBy["..."]; found && groupLen > 1 {
			return fmt.Errorf("'...' must be a sole value in route 'groupBy': %v", r.GroupBy)
		}
	}

	for _, namedMuteTimeInterval := range r.MuteTimeIntervals {
		if _, found := muteTimeIntervals[namedMuteTimeInterval]; !found {
			return fmt.Errorf("mute time interval %q not found", namedMuteTimeInterval)
		}
	}

	for _, namedActiveTimeInterval := range r.ActiveTimeIntervals {
		if _, found := muteTimeIntervals[namedActiveTimeInterval]; !found {
			return fmt.Errorf("time interval %q not found", namedActiveTimeInterval)
		}
	}

	// validate that if defaults are set, they match regex
	if r.GroupInterval != "" && !durationRe.MatchString(r.GroupInterval) {
		return fmt.Errorf("groupInterval %s does not match required regex: %s", r.GroupInterval, durationRe.String())

	}
	if r.GroupWait != "" && !durationRe.MatchString(r.GroupWait) {
		return fmt.Errorf("groupWait %s does not match required regex: %s", r.GroupWait, durationRe.String())
	}

	if r.RepeatInterval != "" && !durationRe.MatchString(r.RepeatInterval) {
		return fmt.Errorf("repeatInterval %s does not match required regex: %s", r.RepeatInterval, durationRe.String())
	}

	children, err := r.ChildRoutes()
	if err != nil {
		return err
	}

	for i := range children {
		if err := validateAlertManagerRoutes(&children[i], receivers, muteTimeIntervals, false); err != nil {
			return fmt.Errorf("route[%d]: %w", i, err)
		}
	}

	return nil
}

func validateIntervals(muteTimeIntervals []monitoringv1alpha1.MuteTimeInterval) (map[string]struct{}, error) {
	muteTimeIntervalNames := make(map[string]struct{}, len(muteTimeIntervals))

	for i, mti := range muteTimeIntervals {
		if err := mti.Validate(); err != nil {
			return nil, fmt.Errorf("mute time interval[%d] is invalid: %w", i, err)
		}
		muteTimeIntervalNames[mti.Name] = struct{}{}
	}
	return muteTimeIntervalNames, nil
}
