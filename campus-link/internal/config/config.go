package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
)

const (
	MaxConfigSize     = 64 * 1024
	CampusSiteAPrefix = "10.81.0.0/24"
	CampusSiteBPrefix = "10.82.0.0/24"
)

type IdentityAuthorization struct {
	URI         string `json:"uri"`
	CurrentSPKI string `json:"current_spki"`
	NextSPKI    string `json:"next_spki,omitempty"`
}

type Relay struct {
	ControlListen        string                           `json:"control_listen"`
	UDPListen            string                           `json:"udp_listen"`
	ControlCert          string                           `json:"control_cert"`
	ControlKey           string                           `json:"control_key"`
	ControlCA            string                           `json:"control_ca"`
	LocalControlIdentity IdentityAuthorization            `json:"local_control_identity"`
	Circuit              string                           `json:"circuit"`
	DeploymentID         string                           `json:"deployment_id"`
	EpochStatePath       string                           `json:"epoch_state_path"`
	Prefixes             map[string]string                `json:"prefixes"`
	ControlIdentities    map[string]IdentityAuthorization `json:"control_identities"`
	StatusPath           string                           `json:"status_path"`
}

type Edge struct {
	Site                 string                `json:"site"`
	Role                 string                `json:"role"`
	Generation           string                `json:"generation"`
	Circuit              string                `json:"circuit"`
	DeploymentID         string                `json:"deployment_id"`
	Prefix               string                `json:"prefix"`
	RemotePrefix         string                `json:"remote_prefix"`
	RelayAddress         string                `json:"relay_address"`
	ControlServerName    string                `json:"control_server_name"`
	ControlCert          string                `json:"control_cert"`
	ControlKey           string                `json:"control_key"`
	ControlCA            string                `json:"control_ca"`
	LocalControlIdentity IdentityAuthorization `json:"local_control_identity"`
	ControlIdentity      IdentityAuthorization `json:"control_identity"`
	DataServerName       string                `json:"data_server_name"`
	DataCert             string                `json:"data_cert"`
	DataKey              string                `json:"data_key"`
	DataCA               string                `json:"data_ca"`
	LocalDataIdentity    IdentityAuthorization `json:"local_data_identity"`
	DataIdentity         IdentityAuthorization `json:"data_identity"`
	TunName              string                `json:"tun_name"`
	MTU                  int                   `json:"mtu"`
	StatusPath           string                `json:"status_path"`
}

func Load(path string, dst any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, MaxConfigSize+1))
	if err != nil {
		return err
	}
	if len(b) > MaxConfigSize {
		return fmt.Errorf("decode %s: configuration exceeds %d bytes", path, MaxConfigSize)
	}
	if dst == nil || reflect.TypeOf(dst).Kind() != reflect.Pointer || reflect.ValueOf(dst).IsNil() {
		return errors.New("configuration destination must be a non-nil pointer")
	}
	if err := validateJSONShape(b, reflect.TypeOf(dst)); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func validateJSONShape(data []byte, dstType reflect.Type) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("top-level configuration must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := validateJSONValue(dec, dstType); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return rejectEscapedObjectKeys(data)
}

func rejectEscapedObjectKeys(data []byte) error {
	type container struct {
		kind      byte
		expectKey bool
	}
	stack := make([]container, 0, 4)
	inString := false
	escaped := false
	keyString := false
	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				if keyString {
					return errors.New("escaped JSON object keys are not canonical")
				}
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
				if keyString && len(stack) != 0 {
					stack[len(stack)-1].expectKey = false
				}
			}
			continue
		}
		switch b {
		case '{':
			stack = append(stack, container{kind: '{', expectKey: true})
		case '[':
			stack = append(stack, container{kind: '['})
		case '}', ']':
			if len(stack) != 0 {
				stack = stack[:len(stack)-1]
			}
		case ',':
			if len(stack) != 0 && stack[len(stack)-1].kind == '{' {
				stack[len(stack)-1].expectKey = true
			}
		case '"':
			inString = true
			keyString = len(stack) != 0 && stack[len(stack)-1].kind == '{' && stack[len(stack)-1].expectKey
		}
	}
	return nil
}

func validateJSONValue(dec *json.Decoder, valueType reflect.Type) error {
	for valueType != nil && valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		fields := exactJSONFields(valueType)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			var childType reflect.Type
			switch {
			case valueType != nil && valueType.Kind() == reflect.Struct:
				var found bool
				childType, found = fields[key]
				if !found {
					return fmt.Errorf("unknown or non-canonical JSON field %q", key)
				}
			case valueType != nil && valueType.Kind() == reflect.Map:
				if valueType.Key().Kind() != reflect.String {
					return errors.New("configuration map key must be a string")
				}
				childType = valueType.Elem()
			}
			if err := validateJSONValue(dec, childType); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		var childType reflect.Type
		if valueType != nil && (valueType.Kind() == reflect.Array || valueType.Kind() == reflect.Slice) {
			childType = valueType.Elem()
		}
		for dec.More() {
			if err := validateJSONValue(dec, childType); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func exactJSONFields(valueType reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	if valueType == nil || valueType.Kind() != reflect.Struct {
		return fields
	}
	for i := 0; i < valueType.NumField(); i++ {
		field := valueType.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name := field.Name
		if tag := field.Tag.Get("json"); tag != "" {
			name = strings.Split(tag, ",")[0]
		}
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}
