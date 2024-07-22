# Go Packet Sniffer and Generator (gopktsniffgen)

`gopktsniffgen` is a flexible network packet analyzer written in Go. 
It provides detailed information about network packets across multiple layers of the OSI model.

## Features

- Captures and analyzes network packets in real-time
- Supports analysis of multiple layers:
    - Layer 1 (Physical): Total packet size
    - Layer 2 (Data Link): Frame information, including MTU, EtherType, and MAC addresses
    - Layer 3 (Network): IP packet details, including version, source/destination IPs, and flags
    - Layer 4 (Transport): TCP segment information, including flags, sequence numbers, and options
    - Layer 7 (Application): Payload data (when available)
- Customizable packet capture through command-line flags
- DNS lookup functionality to capture packets for specific domains
- Generates sample network traffic for analysis

## Usage

```
go run main.go -i <interface_name> -site <website_to_analyze>
```

Example:
```
go run main.go -i en0 -site www.example.com
```

This will capture packets on the specified interface (en0) related to traffic to and from www.example.com.

## Dependencies

- github.com/google/gopacket
- github.com/rs/zerolog

Make sure to install these dependencies before running the program.

## Note

This tool is designed for educational and diagnostic purposes. Ensure you have the necessary permissions before capturing network traffic on any system or network.