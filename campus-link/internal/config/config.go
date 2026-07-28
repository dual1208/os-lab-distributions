package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Relay struct {
	ControlListen string            `json:"control_listen"`
	UDPListen     string            `json:"udp_listen"`
	ControlCert   string            `json:"control_cert"`
	ControlKey    string            `json:"control_key"`
	ControlCA     string            `json:"control_ca"`
	Circuit       string            `json:"circuit"`
	Prefixes      map[string]string `json:"prefixes"`
	StatusPath    string            `json:"status_path"`
}

type Edge struct {
	Site              string `json:"site"`
	Role              string `json:"role"`
	Generation        string `json:"generation"`
	Circuit           string `json:"circuit"`
	Prefix            string `json:"prefix"`
	RemotePrefix      string `json:"remote_prefix"`
	RelayAddress      string `json:"relay_address"`
	ControlServerName string `json:"control_server_name"`
	ControlCert       string `json:"control_cert"`
	ControlKey        string `json:"control_key"`
	ControlCA         string `json:"control_ca"`
	DataServerName    string `json:"data_server_name"`
	DataPeerName      string `json:"data_peer_name"`
	DataCert          string `json:"data_cert"`
	DataKey           string `json:"data_key"`
	DataCA            string `json:"data_ca"`
	TunName           string `json:"tun_name"`
	MTU               int    `json:"mtu"`
	StatusPath        string `json:"status_path"`
}

func Load(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
