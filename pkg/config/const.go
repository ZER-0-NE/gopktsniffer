package config

import "flag"

// Command-line flags
var (
	IntfName       = flag.String("i", "en0", "Interface to read packets from")
	SiteName       = flag.String("site", "www.example.com", "Website to send a request to")
	PacketCount    = flag.Int("count", 50, "Number of packets to capture before stopping")
	StopGeneration = make(chan bool)
)

func Init() {
	flag.Parse()
}
