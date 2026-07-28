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
	Type string `json:"type"`
}

type Error struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}
