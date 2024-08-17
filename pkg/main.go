package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopacketsniffer/pkg/applayer"
	"gopacketsniffer/pkg/config"
	frame2 "gopacketsniffer/pkg/frame"
	"gopacketsniffer/pkg/ippacket"
	"gopacketsniffer/pkg/phylayer"
	"gopacketsniffer/pkg/tcpseg"
	"net"
	"net/http"
	"time"
)

// dnsLookup performs a DNS lookup for the given domain and returns the first IPv4 address
func dnsLookup(domain string) net.IP {
	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Fatal().Err(err)
	}
	for _, ip := range ips {
		ipv4 := ip.To4()
		if ipv4 != nil {
			return ipv4
		}
	}
	return nil
}

// generatePackets sends an HTTP GET request to the specified site to generate network traffic
func generatePackets() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for {
		select {
		case <-config.StopGeneration:
			return
		case <-ticker.C:
			if resp, err := http.Get("http://" + *config.SiteName); err != nil {
				log.Fatal().Err(err)
			} else {
				//time.Sleep(time.Second * 2)
				resp.Body.Close()
				//close(stopGeneration)
				log.Info().Msg("Generated packet")
			}
		}
	}
}

// displayAllLayers prints information about all layers of the packet
func displayAllLayers(packet gopacket.Packet) error {
	bytesOverWire, err := phylayer.ParsePhysicalLayer(packet)
	fmt.Println(bytesOverWire.Info())

	frame, err := frame2.ParseL2Frames(packet)
	if err != nil {
		log.Err(err)
		return errors.New("failed to parse L2 Data Link layer")
	}
	fmt.Println(frame.Info())

	ip, err := ippacket.ParseIv4PPacket(packet)
	if err != nil {
		log.Err(err)
		return errors.New("failed to parse L3 IPv4 layer")

	}
	fmt.Println(ip.Info())

	tcpSegment, err := tcpseg.ParseTcpSegment(packet)
	if err != nil {
		log.Err(err)
		return errors.New("failed to parse L4 TCP layer")
	}
	fmt.Println(tcpSegment.Info(ip))

	// Print application layer payload if available
	appLayer, err := applayer.ParseAppLayer(packet)
	if err != nil {
		log.Err(err)
		return errors.New("failed to parse L7 App layer")
	}
	fmt.Println(appLayer.Info())

	return nil
}

func main() {
	config.Init()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Perform DNS lookup for the specified site
	ipViaDNS := dnsLookup(*config.SiteName)
	log.Info().Msg(ipViaDNS.String())

	log.Info().Msgf("Capturing packets on %s interface", *config.IntfName)

	//go generatePackets() // Generate some network traffic
	//time.Sleep(2 * time.Second) // Wait for 2 seconds to ensure packets are generated

	// Open the network interface for packet capture
	if handle, err := pcap.OpenLive(*config.IntfName, 65536, true, pcap.BlockForever); err != nil {
		log.Fatal().Err(err)
	} else if err := handle.SetBPFFilter("host " + ipViaDNS.String()); err != nil {
		log.Fatal().Err(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		pktIdx := 1
		// Process captured packets
		for packet := range packetSource.Packets() {
			fmt.Printf("\n\n======== PACKET %v =========\n\n", pktIdx)
			if err := displayAllLayers(packet); err != nil {
				log.Err(err)
				errors.New("failed parsing layer")
			}
			pktIdx += 1
			// Stop after capturing defined number of packets (defaults to 50)
			//if pktIdx > *config.PacketCount {
			//	close(config.StopGeneration)
			//	break
			//}
		}
		defer handle.Close()
	}
	// Wait for packet generation to stop
	time.Sleep(1 * time.Second)
}
