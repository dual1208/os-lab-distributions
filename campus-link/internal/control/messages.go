package control

type Register struct {
	Type       string   `json:"type"`
	Site       string   `json:"site"`
	Generation string   `json:"generation"`
	Version    string   `json:"version"`
	Circuit    string   `json:"circuit"`
	Prefix     string   `json:"prefix"`
	Transports []string `json:"transports"`
}

type Registered struct {
	Type      string `json:"type"`
	BindToken string `json:"bind_token"`
}

type Heartbeat struct {
	Type     string `json:"type"`
	Sequence uint64 `json:"sequence"`
}

type HeartbeatAck struct {
	Type     string `json:"type"`
	Sequence uint64 `json:"sequence"`
}

type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// RendezvousPlan is delivered only over the authenticated control session.
// Candidate addresses and ProbeKey must never be included in logs or status.
type RendezvousPlan struct {
	Type           string   `json:"type"`
	Circuit        string   `json:"circuit"`
	Generation     string   `json:"generation"`
	PeerGeneration string   `json:"peer_generation"`
	Session        string   `json:"session"`
	ProbeKey       string   `json:"probe_key"`
	Role           string   `json:"role"`
	Attempt        uint32   `json:"attempt"`
	PathEpoch      uint64   `json:"path_epoch"`
	StartUnix      int64    `json:"start_unix"`
	ExpiresUnix    int64    `json:"expires_unix"`
	Candidates     []string `json:"candidates"`
}

type PathReport struct {
	Type      string `json:"type"`
	Session   string `json:"session"`
	PathEpoch uint64 `json:"path_epoch"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
}
