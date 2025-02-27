// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/mattermost/mattermost-server/v6/model"
)

type ConfigDiffs []ConfigDiff

type ConfigDiff struct {
	Path      string      `json:"path"`
	BaseVal   interface{} `json:"base_val"`
	ActualVal interface{} `json:"actual_val"`
}

var configSensitivePaths = map[string]bool{
	"LdapSettings.BindPassword":                              true,
	"FileSettings.PublicLinkSalt":                            true,
	"FileSettings.AmazonS3SecretAccessKey":                   true,
	"SqlSettings.DataSource":                                 true,
	"SqlSettings.AtRestEncryptKey":                           true,
	"SqlSettings.DataSourceReplicas":                         true,
	"SqlSettings.DataSourceSearchReplicas":                   true,
	"EmailSettings.SMTPPassword":                             true,
	"GitLabSettings.Secret":                                  true,
	"GoogleSettings.Secret":                                  true,
	"Office365Settings.Secret":                               true,
	"OpenIdSettings.Secret":                                  true,
	"ElasticsearchSettings.Password":                         true,
	"MessageExportSettings.GlobalRelaySettings.SMTPUsername": true,
	"MessageExportSettings.GlobalRelaySettings.SMTPPassword": true,
	"MessageExportSettings.GlobalRelaySettings.EmailAddress": true,
	"ServiceSettings.GfycatAPISecret":                        true,
	"ServiceSettings.SplitKey":                               true,
	"PluginSettings.Plugins":                                 true,
}

// Sanitize replaces sensitive config values in the diff with asterisks filled strings.
func (cd ConfigDiffs) Sanitize() ConfigDiffs {
	if len(cd) == 1 {
		cfgPtr, ok := cd[0].BaseVal.(*model.Config)
		if ok {
			cfgPtr.Sanitize()
		}
		cfgPtr, ok = cd[0].ActualVal.(*model.Config)
		if ok {
			cfgPtr.Sanitize()
		}
		cfgVal, ok := cd[0].BaseVal.(model.Config)
		if ok {
			cfgVal.Sanitize()
		}
		cfgVal, ok = cd[0].ActualVal.(model.Config)
		if ok {
			cfgVal.Sanitize()
		}
	}

	for i := range cd {
		if configSensitivePaths[cd[i].Path] {
			cd[i].BaseVal = model.FakeSetting
			cd[i].ActualVal = model.FakeSetting
		}
	}

	return cd
}

func diff(base, actual reflect.Value, structField reflect.StructField, label string, tag, tagValue string) ([]ConfigDiff, error) {
	var diffs []ConfigDiff

	if base.IsZero() && actual.IsZero() {
		return diffs, nil
	}

	if base.IsZero() || actual.IsZero() {
		return append(diffs, ConfigDiff{
			Path:      label,
			BaseVal:   base.Interface(),
			ActualVal: actual.Interface(),
		}), nil
	}

	baseType := base.Type()
	actualType := actual.Type()

	if baseType.Kind() == reflect.Ptr {
		base = reflect.Indirect(base)
		actual = reflect.Indirect(actual)
		baseType = base.Type()
		actualType = actual.Type()
	}

	if baseType != actualType {
		return nil, fmt.Errorf("not same type %s %s", baseType, actualType)
	}

	// skip if not tag scoped, field does not have any tags or if it's just empty
	if tag != "" && string(structField.Tag) != "" && structField.Name != "" {
		// we are getting the diffs scoped with a specific tag
		// therefore we first lookup if the field has the tag, if not we skip
		// to check if it's changed or not as it's out of the scope
		val, ok := structField.Tag.Lookup(tag)
		if !ok {
			return diffs, nil
		}

		// tag scope also cares about the tag value, if we don't have the value
		// there is no need to get the diff
		if !strings.Contains(val, tagValue) {
			return diffs, nil
		}

		// prevent going further scoping according this tag because we are already
		// scoped the struct on higher level
		if baseType.Kind() == reflect.Struct {
			tag = ""
		}
	}

	switch baseType.Kind() {
	case reflect.Struct:
		if base.NumField() != actual.NumField() {
			return nil, fmt.Errorf("not same number of fields in struct")
		}

		for i := 0; i < base.NumField(); i++ {
			fieldLabel := baseType.Field(i).Name
			if label != "" {
				fieldLabel = label + "." + fieldLabel
			}

			d, err := diff(base.Field(i), actual.Field(i), actualType.Field(i), fieldLabel, tag, tagValue)
			if err != nil {
				return nil, err
			}
			diffs = append(diffs, d...)
		}
	default:
		if !reflect.DeepEqual(base.Interface(), actual.Interface()) {
			diffs = append(diffs, ConfigDiff{
				Path:      label,
				BaseVal:   base.Interface(),
				ActualVal: actual.Interface(),
			})
		}
	}

	return diffs, nil
}

// Diff returns the diff between two configs
func Diff(base, actual *model.Config) (ConfigDiffs, error) {
	if base == nil || actual == nil {
		return nil, fmt.Errorf("input configs should not be nil")
	}
	baseVal := reflect.Indirect(reflect.ValueOf(base))
	actualVal := reflect.Indirect(reflect.ValueOf(actual))
	return diff(baseVal, actualVal, reflect.StructField{}, "", "", "")
}

// DiffTags behaves similar with Diff but it is scoped against a tag and it's value
func DiffTags(base, actual *model.Config, tag, value string) (ConfigDiffs, error) {
	if base == nil || actual == nil {
		return nil, fmt.Errorf("input configs should not be nil")
	}
	baseVal := reflect.Indirect(reflect.ValueOf(base))
	actualVal := reflect.Indirect(reflect.ValueOf(actual))
	return diff(baseVal, actualVal, reflect.StructField{}, "", tag, value)
}

func (cd ConfigDiffs) String() string {
	return fmt.Sprintf("%+v", []ConfigDiff(cd))
}
