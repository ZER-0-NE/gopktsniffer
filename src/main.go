package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	frame2 "gopacketsniffer/src/frame"
	"gopacketsniffer/src/ip_packet"
	"gopacketsniffer/src/tcp_segment"
	"net"
	"net/http"
)

// Command-line flags
var intfName = flag.String("i", "en0", "Interface to read packets from")
var siteName = flag.String("site", "www.example.com", "Website to send a request to")

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
	if resp, err := http.Get("http://" + *siteName); err != nil {
		log.Printf("Could not get HTTP: %v", err)
	} else {
		defer resp.Body.Close()
	}
}

// physicalLayerInfo prints information about the physical layer (Layer 1)
func physicalLayerInfo(packet gopacket.Packet) {
	fmt.Printf("\n\n======== LAYER 1 (Physical) =========\n")
	fmt.Printf("TOTAL PACKET BYTES: %v bytes", len(packet.Data()))
}

// frameInfo prints information about the data link layer (Layer 2)
func frameInfo(frame *frame2.L2Frame) {
	fmt.Printf("\n\n======== LAYER 2 (Data Link) =========\n")
	fmt.Printf("[MTU]: %v, \nEtherType: %v, \nL2 Frame: %v > %v", frame.MTU, frame.EtherType, frame.SrcMac, frame.DstMac)
	fmt.Printf("\n[FRAME LEN]: %v", frame.FrameLen)
}

// ipPacketInfo prints information about the IP layer (Layer 3)
func ipPacketInfo(ip *ip_packet.IPv4Packet) {
	fmt.Printf("\n\n======== LAYER 3 (IP) =========\n")
	fmt.Printf("[HEADER LENGTH] %v bytes\n", ip.IHL)
	fmt.Printf("IP Packet Version: %v \n", ip.Version)
	fmt.Printf("Source IP: %v \n", ip.SrcIp)
	fmt.Printf("Destination IP: %v\n", ip.DstIp)
	fmt.Printf("TTL: %v\n", ip.TTL)
	fmt.Printf("[FLAGS]: %v", ip.V4Flags)
}

// tcpSegmentInfo prints information about the TCP layer (Layer 4)
func tcpSegmentInfo(segment *tcp_segment.TCPSegment, ip *ip_packet.IPv4Packet) {
	fmt.Printf("\n\n======== LAYER 4 (TCP/UDP) =========\n")
	fmt.Printf("[SEGMENT LENGTH]: %v\n", len(segment.TCPPayload))
	fmt.Printf("[HEADER LENGTH(DATA OFFSET)]: %v\n", segment.TCPHeader.DataOffset)
	fmt.Printf("[MSS]: %v\n", segment.GetOption(layers.TCPOptionKind(2)))
	fmt.Printf("[WINDOW SIZE]: %v\n", segment.TCPHeader.Window)
	fmt.Printf("[CWR]: %v\n", segment.Flags.CWR)

	// Print information for different TCP flags
	if segment.Flags.SYN {
		fmt.Printf("[SYN] \n[Seq]:%v \n%v:%v > %v:%v\n", segment.TCPHeader.Seq, ip.SrcIp, segment.TCPHeader.SrcPort, ip.DstIp, segment.TCPHeader.DstPort)
	}
	if segment.Flags.SYN && segment.Flags.ACK {
		fmt.Printf("[SYN/ACK] \n[Seq]:%v \n%v:%v > %v:%v\n", segment.TCPHeader.Seq, ip.SrcIp, segment.TCPHeader.SrcPort, ip.DstIp, segment.TCPHeader.DstPort)
	}
	if segment.Flags.ACK {
		fmt.Printf("[ACK NUM]: %v\n", segment.TCPHeader.Ack)
		fmt.Printf("[ACK] \n[Seq]:%v \n%v:%v > %v:%v\n", segment.TCPHeader.Seq, ip.SrcIp, segment.TCPHeader.SrcPort, ip.DstIp, segment.TCPHeader.DstPort)
	}
	if segment.Flags.FIN {
		fmt.Printf("[FIN] \n[Seq]:%v \n%v:%v > %v:%v\n", segment.TCPHeader.Seq, ip.SrcIp, segment.TCPHeader.SrcPort, ip.DstIp, segment.TCPHeader.DstPort)
		fmt.Printf("Closing connection")
	}
	if segment.Flags.RST {
		fmt.Printf("[RST] \n[Seq]:%v \n%v:%v > %v:%v\n", segment.TCPHeader.Seq, ip.SrcIp, segment.TCPHeader.SrcPort, ip.DstIp, segment.TCPHeader.DstPort)
		fmt.Printf("[PORT CLOSE]: %v", segment.TCPHeader.SrcPort)
	}
}

// displayAllLayers prints information about all layers of the packet
func displayAllLayers(packet gopacket.Packet) {
	physicalLayerInfo(packet)

	frame := frame2.Frames(packet)
	frameInfo(frame)

	ipPacket := ip_packet.IPPacket(packet)
	ipPacketInfo(ipPacket)

	tcpSegment := tcp_segment.TcpSegment(packet)
	tcpSegmentInfo(tcpSegment, ipPacket)

	// Print application layer payload if available
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		log.Printf("App layer: %v", string(appLayer.Payload()))
	}
}

func main() {
	// Parse command-line flags
	flag.Parse()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Perform DNS lookup for the specified site
	ipViaDNS := dnsLookup(*siteName)
	log.Info().Msg(ipViaDNS.String())

	log.Info().Msgf("Capturing packets on %s interface", *intfName)

	// Open the network interface for packet capture
	if handle, err := pcap.OpenLive(*intfName, 65536, true, pcap.BlockForever); err != nil {
		log.Fatal().Err(err)
	} else if err := handle.SetBPFFilter("host " + ipViaDNS.String()); err != nil { // Set BPF filter to capture only packets related to the specified host
		log.Fatal().Err(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		generatePackets() // Generate some network traffic
		pktIdx := 1
		// Process captured packets
		for packet := range packetSource.Packets() {
			fmt.Printf("\n\n======== PACKET %v =========\n\n", pktIdx)
			displayAllLayers(packet)
			pktIdx += 1
		}
		defer handle.Close()
	}
}
