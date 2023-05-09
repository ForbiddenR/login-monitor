package afpacket

type config struct {
	// Interface to listen on. Defaults to "any".
	Interface string `config:"socket.dns.af_packet.interface"`
	// Snaplen is the packet snapshot size.
	Snaplen int `config:"socket.dns.af_packet.snalen"`
}

func defaultConfig() config {
	return config{
		Interface: "any",
		Snaplen: 1024,
	}
}