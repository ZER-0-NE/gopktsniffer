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

```
❯ go run main.go -i en0 -site www.example.com
{"level":"info","time":1722256003,"message":"93.184.215.14"}
{"level":"info","time":1722256003,"message":"Capturing packets on en0 interface"}


======== PACKET 1 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [180 167 198 174 19 76 92 82 48 157 70 47 8 0 69 0 0 64 0 0 64 0 64 6 39 204 192 168 29 125 93 184 215 14 220 193 0 80 0 157 196 64 0 0 0 0 176 2 255 255 236 54 0 0 2 4 5 180 1 3 3 6 1 1 8 10 252 59 153 173 0 0 0 0 4 2 0 0]
[TOTAL PACKET BYTES]: 78 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: 5c:52:30:9d:46:2f > b4:a7:c6:ae:13:4c
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 64 bytes
[IP Packet Version]: 4
[Source IP]: 192.168.29.125
[Destination IP]: 93.184.215.14
[TTL]: 64
[FLAGS]: DF


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 0
[HEADER LENGTH(DATA OFFSET)]: 44
[MSS]: TCPOption(MSS:1460 0x05b4)
[WINDOW SIZE]: 65535
[CWR]: false

[SYN]
[Seq]:10339392
192.168.29.125:56513 > 93.184.215.14:80(http)



======== PACKET 2 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [92 82 48 157 70 47 180 167 198 174 19 76 8 0 69 0 0 60 0 0 64 0 47 6 56 208 93 184 215 14 192 168 29 125 0 80 220 193 120 66 174 157 0 157 196 65 160 18 255 255 94 174 0 0 2 4 5 180 4 2 8 10 99 195 19 214 252 59 153 173 1 3 3 9]
[TOTAL PACKET BYTES]: 74 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: b4:a7:c6:ae:13:4c > 5c:52:30:9d:46:2f
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 60 bytes
[IP Packet Version]: 4
[Source IP]: 93.184.215.14
[Destination IP]: 192.168.29.125
[TTL]: 47
[FLAGS]: DF


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 0
[HEADER LENGTH(DATA OFFSET)]: 40
[MSS]: TCPOption(MSS:1460 0x05b4)
[WINDOW SIZE]: 65535
[CWR]: false

[SYN]
[Seq]:2017635997
93.184.215.14:80(http) > 192.168.29.125:56513

[SYN/ACK]
[Seq]:2017635997
93.184.215.14:80(http) > 192.168.29.125:56513
[ACK NUM]: 10339393

[ACK]
[Seq]:2017635997
93.184.215.14:80(http) > 192.168.29.125:56513



======== PACKET 3 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [180 167 198 174 19 76 92 82 48 157 70 47 8 0 69 0 0 52 0 0 64 0 64 6 39 216 192 168 29 125 93 184 215 14 220 193 0 80 0 157 196 65 120 66 174 158 128 16 8 10 132 136 0 0 1 1 8 10 252 59 154 151 99 195 19 214]
[TOTAL PACKET BYTES]: 66 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: 5c:52:30:9d:46:2f > b4:a7:c6:ae:13:4c
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 52 bytes
[IP Packet Version]: 4
[Source IP]: 192.168.29.125
[Destination IP]: 93.184.215.14
[TTL]: 64
[FLAGS]: DF


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 0
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 2058
[CWR]: false
[ACK NUM]: 2017635998

[ACK]
[Seq]:10339393
192.168.29.125:56513 > 93.184.215.14:80(http)



======== PACKET 4 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [180 167 198 174 19 76 92 82 48 157 70 47 8 0 69 0 0 131 0 0 64 0 64 6 39 137 192 168 29 125 93 184 215 14 220 193 0 80 0 157 196 65 120 66 174 158 128 24 8 10 241 178 0 0 1 1 8 10 252 59 154 151 99 195 19 214 71 69 84 32 47 32 72 84 84 80 47 49 46 49 13 10 72 111 115 116 58 32 119 119 119 46 101 120 97 109 112 108 101 46 99 111 109 13 10 85 115 101 114 45 65 103 101 110 116 58 32 99 117 114 108 47 55 46 56 52 46 48 13 10 65 99 99 101 112 116 58 32 42 47 42 13 10 13 10]
[TOTAL PACKET BYTES]: 145 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: 5c:52:30:9d:46:2f > b4:a7:c6:ae:13:4c
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 131 bytes
[IP Packet Version]: 4
[Source IP]: 192.168.29.125
[Destination IP]: 93.184.215.14
[TTL]: 64
[FLAGS]: DF


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 79
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 2058
[CWR]: false
[ACK NUM]: 2017635998

[ACK]
[Seq]:10339393
192.168.29.125:56513 > 93.184.215.14:80(http)


======== LAYER 7 (APP) =========
[TOTAL PAYLOAD]: 79 bytes
[PAYLOAD]: GET / HTTP/1.1
Host: www.example.com
User-Agent: curl/7.84.0
Accept: */*




======== PACKET 5 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [92 82 48 157 70 47 180 167 198 174 19 76 8 0 69 0 0 52 28 155 0 0 47 6 92 61 93 184 215 14 192 168 29 125 0 80 220 193 120 66 174 158 0 157 196 144 128 16 0 128 138 216 0 0 1 1 8 10 99 195 20 193 252 59 154 151]
[TOTAL PACKET BYTES]: 66 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: b4:a7:c6:ae:13:4c > 5c:52:30:9d:46:2f
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 52 bytes
[IP Packet Version]: 4
[Source IP]: 93.184.215.14
[Destination IP]: 192.168.29.125
[TTL]: 47
[FLAGS]:


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 0
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 128
[CWR]: false
[ACK NUM]: 10339472

[ACK]
[Seq]:2017635998
93.184.215.14:80(http) > 192.168.29.125:56513



======== PACKET 6 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [92 82 48 157 70 47 180 167 198 174 19 76 8 0 69 0 5 220 28 156 0 0 47 6 86 148 93 184 215 14 192 168 29 125 0 80 220 193 120 66 174 158 0 157 196 144 128 16 0 128 211 152 0 0 1 1 8 10 99 195 20 194 252 59 154 151 72 84 84 80 47 49 46 49 32 50 48 48 32 79 75 13 10 65 99 99 101 112 116 45 82 97 110 103 101 115 58 32 98 121 116 101 115 13 10 65 103 101 58 32 53 52 54 57 56 50 13 10 67 97 99 104 101 45 67 111 110 116 114 111 108 58 32 109 97 120 45 97 103 101 61 54 48 52 56 48 48 13 10 67 111 110 116 101 110 116 45 84 121 112 101 58 32 116 101 120 116 47 104 116 109 108 59 32 99 104 97 114 115 101 116 61 85 84 70 45 56 13 10 68 97 116 101 58 32 77 111 110 44 32 50 57 32 74 117 108 32 50 48 50 52 32 49 50 58 50 54 58 52 56 32 71 77 84 13 10 69 116 97 103 58 32 34 51 49 52 55 53 50 54 57 52 55 34 13 10 69 120 112 105 114 101 115 58 32 77 111 110 44 32 48 53 32 65 117 103 32 50 48 50 52 32 49 50 58 50 54 58 52 56 32 71 77 84 13 10 76 97 115 116 45 77 111 100 105 102 105 101 100 58 32 84 104 117 44 32 49 55 32 79 99 116 32 50 48 49 57 32 48 55 58 49 56 58 50 54 32 71 77 84 13 10 83 101 114 118 101 114 58 32 69 67 65 99 99 32 40 110 121 100 47 68 49 54 67 41 13 10 86 97 114 121 58 32 65 99 99 101 112 116 45 69 110 99 111 100 105 110 103 13 10 88 45 67 97 99 104 101 58 32 72 73 84 13 10 67 111 110 116 101 110 116 45 76 101 110 103 116 104 58 32 49 50 53 54 13 10 13 10 60 33 100 111 99 116 121 112 101 32 104 116 109 108 62 10 60 104 116 109 108 62 10 60 104 101 97 100 62 10 32 32 32 32 60 116 105 116 108 101 62 69 120 97 109 112 108 101 32 68 111 109 97 105 110 60 47 116 105 116 108 101 62 10 10 32 32 32 32 60 109 101 116 97 32 99 104 97 114 115 101 116 61 34 117 116 102 45 56 34 32 47 62 10 32 32 32 32 60 109 101 116 97 32 104 116 116 112 45 101 113 117 105 118 61 34 67 111 110 116 101 110 116 45 116 121 112 101 34 32 99 111 110 116 101 110 116 61 34 116 101 120 116 47 104 116 109 108 59 32 99 104 97 114 115 101 116 61 117 116 102 45 56 34 32 47 62 10 32 32 32 32 60 109 101 116 97 32 110 97 109 101 61 34 118 105 101 119 112 111 114 116 34 32 99 111 110 116 101 110 116 61 34 119 105 100 116 104 61 100 101 118 105 99 101 45 119 105 100 116 104 44 32 105 110 105 116 105 97 108 45 115 99 97 108 101 61 49 34 32 47 62 10 32 32 32 32 60 115 116 121 108 101 32 116 121 112 101 61 34 116 101 120 116 47 99 115 115 34 62 10 32 32 32 32 98 111 100 121 32 123 10 32 32 32 32 32 32 32 32 98 97 99 107 103 114 111 117 110 100 45 99 111 108 111 114 58 32 35 102 48 102 48 102 50 59 10 32 32 32 32 32 32 32 32 109 97 114 103 105 110 58 32 48 59 10 32 32 32 32 32 32 32 32 112 97 100 100 105 110 103 58 32 48 59 10 32 32 32 32 32 32 32 32 102 111 110 116 45 102 97 109 105 108 121 58 32 45 97 112 112 108 101 45 115 121 115 116 101 109 44 32 115 121 115 116 101 109 45 117 105 44 32 66 108 105 110 107 77 97 99 83 121 115 116 101 109 70 111 110 116 44 32 34 83 101 103 111 101 32 85 73 34 44 32 34 79 112 101 110 32 83 97 110 115 34 44 32 34 72 101 108 118 101 116 105 99 97 32 78 101 117 101 34 44 32 72 101 108 118 101 116 105 99 97 44 32 65 114 105 97 108 44 32 115 97 110 115 45 115 101 114 105 102 59 10 32 32 32 32 32 32 32 32 10 32 32 32 32 125 10 32 32 32 32 100 105 118 32 123 10 32 32 32 32 32 32 32 32 119 105 100 116 104 58 32 54 48 48 112 120 59 10 32 32 32 32 32 32 32 32 109 97 114 103 105 110 58 32 53 101 109 32 97 117 116 111 59 10 32 32 32 32 32 32 32 32 112 97 100 100 105 110 103 58 32 50 101 109 59 10 32 32 32 32 32 32 32 32 98 97 99 107 103 114 111 117 110 100 45 99 111 108 111 114 58 32 35 102 100 102 100 102 102 59 10 32 32 32 32 32 32 32 32 98 111 114 100 101 114 45 114 97 100 105 117 115 58 32 48 46 53 101 109 59 10 32 32 32 32 32 32 32 32 98 111 120 45 115 104 97 100 111 119 58 32 50 112 120 32 51 112 120 32 55 112 120 32 50 112 120 32 114 103 98 97 40 48 44 48 44 48 44 48 46 48 50 41 59 10 32 32 32 32 125 10 32 32 32 32 97 58 108 105 110 107 44 32 97 58 118 105 115 105 116 101 100 32 123 10 32 32 32 32 32 32 32 32 99 111 108 111 114 58 32 35 51 56 52 56 56 102 59 10 32 32 32 32 32 32 32 32 116 101 120 116 45 100 101 99 111 114 97 116 105 111 110 58 32 110 111 110 101 59 10 32 32 32 32 125 10 32 32 32 32 64 109 101 100 105 97 32 40 109 97 120 45 119 105 100 116 104 58 32 55 48 48 112 120 41 32 123 10 32 32 32 32 32 32 32 32 100 105 118 32 123 10 32 32 32 32 32 32 32 32 32 32 32 32 109 97 114 103 105 110 58 32 48 32 97 117 116 111 59 10 32 32 32 32 32 32 32 32 32 32 32 32 119 105 100 116 104 58 32 97 117 116 111 59 10 32 32 32 32 32 32 32 32 125 10 32 32 32 32 125 10 32 32 32 32 60 47 115 116 121 108 101 62 32 32 32 32 10 60 47 104 101 97 100 62 10 10 60 98 111 100 121 62 10 60 100 105 118 62 10 32 32 32 32 60 104 49 62 69 120 97 109 112 108 101 32 68 111 109 97 105 110 60 47 104 49 62 10 32 32 32 32 60 112 62 84 104 105 115 32 100 111 109 97 105 110 32 105 115 32 102 111 114 32 117 115 101 32 105 110 32 105 108 108 117 115 116 114 97 116 105 118 101 32 101 120 97 109 112 108 101 115 32 105 110 32 100 111 99 117 109 101 110 116 115 46 32 89 111 117 32 109 97 121 32 117 115 101 32 116 104 105 115 10 32 32 32 32 100 111 109 97 105 110 32 105 110 32 108 105 116 101 114 97 116 117 114 101 32 119]
[TOTAL PACKET BYTES]: 1514 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: b4:a7:c6:ae:13:4c > 5c:52:30:9d:46:2f
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 1500 bytes
[IP Packet Version]: 4
[Source IP]: 93.184.215.14
[Destination IP]: 192.168.29.125
[TTL]: 47
[FLAGS]:


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 1448
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 128
[CWR]: false
[ACK NUM]: 10339472

[ACK]
[Seq]:2017635998
93.184.215.14:80(http) > 192.168.29.125:56513


======== LAYER 7 (APP) =========
[TOTAL PAYLOAD]: 1448 bytes
[PAYLOAD]: HTTP/1.1 200 OK
Accept-Ranges: bytes
Age: 546982
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Mon, 29 Jul 2024 12:26:48 GMT
Etag: "3147526947"
Expires: Mon, 05 Aug 2024 12:26:48 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECAcc (nyd/D16C)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1256

<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;

    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature w


======== PACKET 7 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [92 82 48 157 70 47 180 167 198 174 19 76 8 0 69 0 0 213 28 157 0 0 47 6 91 154 93 184 215 14 192 168 29 125 0 80 220 193 120 66 180 70 0 157 196 144 128 24 0 128 90 172 0 0 1 1 8 10 99 195 20 194 252 59 154 151 105 116 104 111 117 116 32 112 114 105 111 114 32 99 111 111 114 100 105 110 97 116 105 111 110 32 111 114 32 97 115 107 105 110 103 32 102 111 114 32 112 101 114 109 105 115 115 105 111 110 46 60 47 112 62 10 32 32 32 32 60 112 62 60 97 32 104 114 101 102 61 34 104 116 116 112 115 58 47 47 119 119 119 46 105 97 110 97 46 111 114 103 47 100 111 109 97 105 110 115 47 101 120 97 109 112 108 101 34 62 77 111 114 101 32 105 110 102 111 114 109 97 116 105 111 110 46 46 46 60 47 97 62 60 47 112 62 10 60 47 100 105 118 62 10 60 47 98 111 100 121 62 10 60 47 104 116 109 108 62 10]
[TOTAL PACKET BYTES]: 227 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: b4:a7:c6:ae:13:4c > 5c:52:30:9d:46:2f
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 213 bytes
[IP Packet Version]: 4
[Source IP]: 93.184.215.14
[Destination IP]: 192.168.29.125
[TTL]: 47
[FLAGS]:


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 161
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 128
[CWR]: false
[ACK NUM]: 10339472

[ACK]
[Seq]:2017637446
93.184.215.14:80(http) > 192.168.29.125:56513


======== LAYER 7 (APP) =========
[TOTAL PAYLOAD]: 161 bytes
[PAYLOAD]: ithout prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>



======== PACKET 8 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [180 167 198 174 19 76 92 82 48 157 70 47 8 0 69 0 0 52 0 0 64 0 64 6 39 216 192 168 29 125 93 184 215 14 220 193 0 80 0 157 196 144 120 66 180 231 128 16 7 241 124 49 0 0 1 1 8 10 252 59 155 131 99 195 20 194]
[TOTAL PACKET BYTES]: 66 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: 5c:52:30:9d:46:2f > b4:a7:c6:ae:13:4c
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 52 bytes
[IP Packet Version]: 4
[Source IP]: 192.168.29.125
[Destination IP]: 93.184.215.14
[TTL]: 64
[FLAGS]: DF


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 0
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 2033
[CWR]: false
[ACK NUM]: 2017637607

[ACK]
[Seq]:10339472
192.168.29.125:56513 > 93.184.215.14:80(http)



======== PACKET 9 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [180 167 198 174 19 76 92 82 48 157 70 47 8 0 69 0 0 52 0 0 64 0 64 6 39 216 192 168 29 125 93 184 215 14 220 193 0 80 0 157 196 144 120 66 180 231 128 17 8 0 124 33 0 0 1 1 8 10 252 59 155 131 99 195 20 194]
[TOTAL PACKET BYTES]: 66 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: 5c:52:30:9d:46:2f > b4:a7:c6:ae:13:4c
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 52 bytes
[IP Packet Version]: 4
[Source IP]: 192.168.29.125
[Destination IP]: 93.184.215.14
[TTL]: 64
[FLAGS]: DF


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 0
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 2048
[CWR]: false
[ACK NUM]: 2017637607

[ACK]
[Seq]:10339472
192.168.29.125:56513 > 93.184.215.14:80(http)

[FIN]
[Seq]:10339472
192.168.29.125:56513 > 93.184.215.14:80(http)
Closing connection



======== PACKET 10 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [92 82 48 157 70 47 180 167 198 174 19 76 8 0 69 0 0 52 28 158 0 0 47 6 92 58 93 184 215 14 192 168 29 125 0 80 220 193 120 66 180 231 0 157 196 145 128 17 0 128 130 182 0 0 1 1 8 10 99 195 21 172 252 59 155 131]
[TOTAL PACKET BYTES]: 66 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: b4:a7:c6:ae:13:4c > 5c:52:30:9d:46:2f
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 52 bytes
[IP Packet Version]: 4
[Source IP]: 93.184.215.14
[Destination IP]: 192.168.29.125
[TTL]: 47
[FLAGS]:


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 0
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 128
[CWR]: false
[ACK NUM]: 10339473

[ACK]
[Seq]:2017637607
93.184.215.14:80(http) > 192.168.29.125:56513

[FIN]
[Seq]:2017637607
93.184.215.14:80(http) > 192.168.29.125:56513
Closing connection



======== PACKET 11 =========




======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: [180 167 198 174 19 76 92 82 48 157 70 47 8 0 69 0 0 52 0 0 64 0 64 6 39 216 192 168 29 125 93 184 215 14 220 193 0 80 0 157 196 145 120 66 180 232 128 16 8 0 122 77 0 0 1 1 8 10 252 59 156 108 99 195 21 172]
[TOTAL PACKET BYTES]: 66 bytes



======== LAYER 2 (Data Link) =========
[MTU]: 1500 bytes
EtherType: IPv4
L2 Frame: 5c:52:30:9d:46:2f > b4:a7:c6:ae:13:4c
[FRAME LEN]: 0



======== LAYER 3 (IP) =========
[HEADER LENGTH]: 20 bytes
[Total Length]: 52 bytes
[IP Packet Version]: 4
[Source IP]: 192.168.29.125
[Destination IP]: 93.184.215.14
[TTL]: 64
[FLAGS]: DF


======== LAYER 4 (TCP) =========
[SEGMENT LENGTH]: 0
[HEADER LENGTH(DATA OFFSET)]: 32
[WINDOW SIZE]: 2048
[CWR]: false
[ACK NUM]: 2017637608

[ACK]
[Seq]:10339473
192.168.29.125:56513 > 93.184.215.14:80(http)

```

## Dependencies

- github.com/google/gopacket
- github.com/rs/zerolog

Make sure to install these dependencies before running the program.

## Note

This tool is designed for educational and diagnostic purposes. Ensure you have the necessary permissions before capturing network traffic on any system or network.