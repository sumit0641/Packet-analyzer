# DPI Engine - Deep Packet Inspection System


This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `src/main_working.cpp` | Learning, small captures |
| Multi-threaded | `src/dpi_mt.cpp` | Production, large captures |

---

## 4. File Structure

```
packet_analyzer/
├── include/                    # Header files (declarations)
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Network protocol parsing
│   ├── sni_extractor.h        # TLS/HTTP inspection
│   ├── types.h                # Data structures (FiveTuple, AppType, etc.)
│   ├── rule_manager.h         # Blocking rules (multi-threaded version)
│   ├── connection_tracker.h   # Flow tracking (multi-threaded version)
│   ├── load_balancer.h        # LB thread (multi-threaded version)
│   ├── fast_path.h            # FP thread (multi-threaded version)
│   ├── thread_safe_queue.h    # Thread-safe queue
│   └── dpi_engine.h           # Main orchestrator
├── src/                        # Source files
│   ├── PcapReader.java        # PCAP file reading
│   ├── PacketParser.java      # Network protocol parsing
│   ├── SniExtractor.java      # TLS/HTTP inspection
│   ├── Types.java             # Data structures (FiveTuple, AppType, etc.)
│   ├── RuleManager.java       # Blocking rules (multi-threaded version)
│   ├── ConnectionTracker.java # Flow tracking (multi-threaded version)
│   ├── LoadBalancer.java      # LB thread (multi-threaded version)
│   ├── FastPath.java          # FP thread (multi-threaded version)
│   ├── ThreadSafeQueue.java   # Thread-safe queue
│   ├── DpiEngine.java         # Main orchestrator
│   ├── MainWorking.java       # ★ SIMPLE VERSION ★
│   └── DpiMT.java             # ★ MULTI-THREADED VERSION ★
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `main_working.cpp`:

### Step 1: Read PCAP File

```
PcapReader reader = new PcapReader();
reader.open("capture.pcap");
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return false when no more packets

### Step 3: Parse Protocol Headers

```
PacketParser.parse(raw, parsed);
```

**What happens (in packet_parser.cpp):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.src_port = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.has_tcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```
FiveTuple tuple = new FiveTuple();
tuple.srcIp = parseIP(parsed.srcIp);
tuple.dstIp = parseIP(parsed.destIp);
tuple.srcPort = parsed.srcPort;
tuple.dstPort = parsed.destPort;
tuple.protocol = parsed.protocol;

Flow flow = flows.computeIfAbsent(tuple, k -> new Flow());  // Get or create
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```
// For HTTPS traffic (port 443)
if (pkt.tuple.dstPort == 443 && pkt.payloadLength > 5) {
    Optional<String> sni = SniExtractor.extract(payload, payloadLength);
    if (sni.isPresent()) {
        flow.sni = sni.get();                    // "[www.youtube.com](https://www.youtube.com)"
        flow.appType = sniToAppType(sni.get());  // AppType.YOUTUBE
    }
}
```

**What happens (in sni_extractor.cpp):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```
   // In Types.java
   if (sni.contains("youtube")) {
   return AppType.YOUTUBE;
   }
   ```

### Step 6: Check Blocking Rules

```
if (rules.isBlocked(tuple.srcIp, flow.appType, flow.sni)) {
    flow.blocked = true;
}
```

**What happens:**
```
// Check IP blacklist
if (blockedIps.contains(srcIp)) return true;

// Check app blacklist
if (blockedApps.contains(app)) return true;

// Check domain blacklist (substring match)
for (String dom : blockedDomains) {
    if (sni.contains(dom)) return true;
}

return false;
```

### Step 7: Forward or Drop

```
if (flow.blocked) {
    dropped++;
    // Don't write to output
} else {
    forwarded++;
    // Write packet to output file
    output.write(packetHeader);
    output.write(packetData);
}
```

### Step 8: Generate Report

After processing all packets:
```
// Count apps
for (Map.Entry<FiveTuple, Flow> entry : flows.entrySet()) {
    appStats.put(entry.getValue().appType, appStats.getOrDefault(entry.getValue().appType, 0) + 1);
}

// Print report
"YouTube: 150 packets (15%)"
"Facebook: 80 packets (8%)"
// ...
...
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`dpi_mt.cpp`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread

```
// Main thread reads PCAP
while (reader.readNextPacket(raw)) {
    Packet pkt = createPacket(raw);
    
    // Hash to select Load Balancer
    int lbIdx = Math.abs(pkt.tuple.hashCode()) % numLbs;
    
    // Push to LB's queue
    lbs[lbIdx].getQueue().push(pkt);
}
```

#### Step 2: Load Balancer Thread

```
public void run() {
    while (running) {
        try {
            // Pop from my input queue
            Packet pkt = inputQueue.pop();
            
            // Hash to select Fast Path
            int fpIdx = Math.abs(pkt.tuple.hashCode()) % numFps;
            
            // Push to FP's queue
            fps[fpIdx].getQueue().push(pkt);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
```

#### Step 3: Fast Path Thread

```
public void run() {
    while (running) {
        try {
            // Pop from my input queue
            Packet pkt = inputQueue.pop();
            
            // Look up flow (each FP has its own flow table)
            Flow flow = flows.computeIfAbsent(pkt.tuple, k -> new Flow());
            
            // Classify (SNI extraction)
            classifyFlow(pkt, flow);
            
            // Check rules
            if (rules.isBlocked(pkt.tuple.srcIp, flow.appType, flow.sni)) {
                stats.dropped++;
            } else {
                // Forward: push to output queue
                outputQueue.push(pkt);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
```

#### Step 4: Output Writer Thread

```
public void run() {
    while (running || outputQueue.size() > 0) {
        try {
            Packet pkt = outputQueue.pop();
            
            // Write to output file
            outputFile.write(packetHeader);
            outputFile.write(pkt.data);
        } catch (InterruptedException | IOException e) {
            // Handle exceptions
        }
    }
}
```

### Thread-Safe Queue

The magic that makes multi-threading work:

```
public class TSQueue<T> {
    private final Queue<T> queue = new LinkedList<>();

    public synchronized void push(T item) {
        queue.add(item);
        notifyAll();  // Wake up waiting consumer
    }

    public synchronized T pop() throws InterruptedException {
        while (queue.isEmpty()) {
            wait();
        }
        return queue.poll();
    }
    
    public synchronized int size() {
        return queue.size();
    }
}
```

**How it works:**
- `push()`: Producer adds item, signals waiting consumers
- `pop()`: Consumer waits until item available, then takes it
- `mutex`: Only one thread can access at a time
- `condition_variable`: Efficient waiting (no busy-loop)

---

## 7. Deep Dive: Each Component

### pcap_reader.h / pcap_reader.cpp

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```
public class PcapGlobalHeader {
    public long magicNumber;   // 0xa1b2c3d4 identifies PCAP
    public int versionMajor;   // Usually 2
    public int versionMinor;   // Usually 4
    public long snaplen;       // Max packet size captured
    public long network;       // 1 = Ethernet
}

public class PcapPacketHeader {
    public long tsSec;         // Timestamp (seconds)
    public long tsUsec;        // Timestamp (microseconds)
    public long inclLen;       // Bytes saved in file
    public long origLen;       // Original packet size
}
```

**Key functions:**
- `open(filename)`: Open PCAP, validate header
- `readNextPacket(raw)`: Read next packet into buffer
- `close()`: Clean up

### packet_parser.h / packet_parser.cpp

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```
public static boolean parse(RawPacket raw, ParsedPacket parsed) {
    parseEthernet(...);  // Extract MACs, EtherType
    parseIPv4(...);      // Extract IPs, protocol, TTL
    parseTCP(...);       // Extract ports, flags, seq numbers
    // OR
    parseUDP(...);       // Extract ports
    return true;
}
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). Your computer might use little-endian. We use `ntohs()` and `ntohl()` to convert:
```
ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);

// Network TO Host Short (16-bit)
short port = buffer.getShort();

// Network TO Host Long (32-bit)
int seq = buffer.getInt();
```

### sni_extractor.h / sni_extractor.cpp

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```
public static Optional<String> extract(byte[] payload, int length) {
    // 1. Verify TLS record header
    // 2. Verify Client Hello handshake
    // 3. Skip to extensions
    // 4. Find SNI extension (type 0x0000)
    // 5. Extract hostname string
}
```

**For HTTP:**
```
public static Optional<String> extractHttpHost(byte[] payload, int length) {
    // 1. Verify HTTP request (GET, POST, etc.)
    // 2. Search for "Host: " header
    // 3. Extract value until newline
}
```

### types.h / types.cpp

**Purpose:** Define data structures used throughout

**FiveTuple:**
```
public class FiveTuple {
    public long srcIp;
    public long dstIp;
    public int srcPort;
    public int dstPort;
    public int protocol;
    
    @Override
    public boolean equals(Object o) { ... }
    
    @Override
    public int hashCode() { ... }
}
```

**AppType:**
```
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK
    // ... more apps
}
```

**sniToAppType function:**
```
public static AppType sniToAppType(String sni) {
    if (sni.contains("youtube")) 
        return AppType.YOUTUBE;
    if (sni.contains("facebook")) 
        return AppType.FACEBOOK;
    // ... more patterns
    return AppType.UNKNOWN;
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```
public static Optional<String> extract(byte[] payload, int length) {
    // Check TLS record header
    if (payload[0] != 0x16) return Optional.empty();  // Not handshake
    if (payload[5] != 0x01) return Optional.empty();  // Not Client Hello
    
    int offset = 43;  // Skip to session ID
    
    // Skip Session ID
    int sessionLen = Byte.toUnsignedInt(payload[offset]);
    offset += 1 + sessionLen;
    
    // Skip Cipher Suites
    int cipherLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
    offset += 2 + cipherLen;
    
    // Skip Compression Methods
    int compLen = Byte.toUnsignedInt(payload[offset]);
    offset += 1 + compLen;
    
    // Read Extensions Length
    int extLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
    offset += 2;
    
    // Search for SNI extension
    int extEnd = offset + extLen;
    while (offset + 4 <= extEnd) {
        int extType = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        int extDataLen = ((payload[offset + 2] & 0xFF) << 8) | (payload[offset + 3] & 0xFF);
        offset += 4;
        
        if (extType == 0x0000) {  // SNI!
            // Parse SNI structure
            int sniLen = ((payload[offset + 3] & 0xFF) << 8) | (payload[offset + 4] & 0xFF);
            return Optional.of(new String(payload, offset + 5, sniLen, StandardCharsets.UTF_8));
        }
        
        offset += extDataLen;
    }
    
    return Optional.empty();  // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **macOS/Linux or Windows with Java JDK 11+ installed
- No external libraries needed!

### Build Commands

**Simple Version:**
```bash
javac -d bin src/*.java
```

**Multi-threaded Version:**
```bash
java -cp bin MainWorking test_dpi.pcap output.pcap
```

### Running

**Basic usage:**
```bash
./dpi_engine test_dpi.pcap output.pcap
```

**With blocking:**
```bash
java -cp bin DpiMT test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure threads (multi-threaded only):**
```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

### Creating Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:               0                              ║
║   FP2 processed:               0                              ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
  ...
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of threads created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across threads |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   ```
   // In Types.java
if (sni.contains("twitch"))
    return AppType.TWITCH;
   ```

2. **Add Bandwidth Throttling**
   ```
   // Instead of DROP, delay packets
if (shouldThrottle(flow)) {
    try {
        Thread.sleep(10);
    } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
    }
}
   ```

3. **Add Live Statistics Dashboard**
   ```// Separate thread printing stats every second
public void runStatsThread() {
    while (running) {
        printStats();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
   ```

4. **Add QUIC/HTTP3 Support**
   - QUIC uses UDP on port 443
   - SNI is in the Initial packet (encrypted differently)

5. **Add Persistent Rules**
   - Save rules to file
   - Load on startup

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Questions?

If you have questions about any part of this project, the code is well-commented and follows the same flow described in this document. Start with the simple version (`main_working.cpp`) to understand the concepts, then move to the multi-threaded version (`dpi_mt.cpp`) to see how parallelism is added.

Happy learning! 🚀
