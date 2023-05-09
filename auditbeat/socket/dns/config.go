package dns

type config struct {
	// Enable toggles the DNS monitoring feature.
	Enable bool `config:"socket.dns.enable"`
	// Type is the dns monitoring implementation used.
	Type string `config:"socket.dns.type"`
}

func defaultConfig() config {
	return config{
		Enable: true,
		Type:   "af_packet",
	}
}
