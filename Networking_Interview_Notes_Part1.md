# Networking for Cybersecurity Interviews — PART 1: Fundamentals
### (Companies + Question Research Summary + Complete Notes with Interview Q&A)

---

## 0. Research Summary — Who's Hiring & What They Ask

**Companies actively hiring Cyber Security interns (2026):**
- **Big 4 / Consulting:** Deloitte (Cyber Summer Scholars), PwC (Cybersecurity & Privacy — 90%+ intern-to-full-time conversion), EY (Cybersecurity internships, 4–6 months), KPMG (Cyber Advisory, 10-week program), Accenture Security
- **Big Tech:** Microsoft, Google, Amazon, IBM
- **Pure-play Security Vendors:** Cisco, Palo Alto Networks, CrowdStrike, Fortinet, Cloudflare
- **Defense/Govt (US):** NSA, Lockheed Martin, Northrop Grumman, Raytheon; **India:** DRDO
- **BFSI:** JP Morgan, Bank of America, major Indian banks
- **India-specific:** TCS, Infosys, Wipro, HCL (via off-campus/on-campus drives)

**Interview format observed (e.g., Deloitte pattern):** 3 rounds — (1) Resume/HR discussion, (2) Technical round covering Python, security concepts, and **networking**, (3) Managerial/behavioral round with a few technical follow-ups.

**Skills recruiters consistently screen for:** networking fundamentals (OSI/TCP-IP, subnetting), Linux basics, Python scripting, firewalls (Cisco ASA/Palo Alto/Fortinet), IDS/IPS (Snort/Suricata/Zeek), SIEM familiarity, VPNs, wireless security (WPA2/WPA3), and cloud security basics.

**Why networking is split into two parts:** Interviewers test networking in two distinct "modes" — (1) **core fundamentals** (how data actually moves — OSI, TCP/IP, addressing, DNS, HTTP/S) used to check you understand the plumbing, and (2) **security-applied networking** (firewalls, IDS/IPS, VPNs, attacks, packet analysis) used to check you can defend it. This file covers **Part 1 — Fundamentals**. Part 2 (Security-Applied Networking) is a separate file.

---

## 1. OSI Model vs TCP/IP Model

### Notes
| Layer (OSI) | Function | Example Protocols/Devices |
|---|---|---|
| 7. Application | User-facing services | HTTP, FTP, DNS, SMTP |
| 6. Presentation | Data format, encryption, compression | SSL/TLS, JPEG, ASCII |
| 5. Session | Establishes/maintains/ends sessions | NetBIOS, RPC |
| 4. Transport | End-to-end delivery, reliability | TCP, UDP |
| 3. Network | Logical addressing, routing | IP, ICMP, routers |
| 2. Data Link | Physical addressing, framing | MAC address, switches, ARP |
| 1. Physical | Raw bit transmission | Cables, NICs, hubs |

TCP/IP model condenses this into **4 layers**: Application, Transport, Internet, Network Access.

Interviewers rarely want you to recite all 7 layers robotically — they want to see you can **map an attack or tool to a layer** (e.g., ARP spoofing = Layer 2, DNS spoofing = Layer 7/Application via resolution, SYN flood = Layer 4).

### Interview Q&A
**Q1: Explain the OSI model and why it matters in security.**
A: The OSI model has 7 layers describing how data moves from an application on one machine to an application on another. It matters in security because different attacks and defenses live at different layers — e.g., MAC spoofing/ARP poisoning at Layer 2, IP spoofing at Layer 3, SYN floods at Layer 4, and SQL injection/XSS at Layer 7. Understanding the layer helps you pick the right control (a firewall for L3/L4 traffic vs a WAF for L7).

**Q2: Why does the industry use TCP/IP more than OSI in practice?**
A: TCP/IP is the model the actual internet is built on — it's simpler (4 layers) and maps directly to real protocols in use (IP, TCP/UDP, HTTP). OSI is mainly a *teaching/reference* model used to reason about where a technology or attack fits.

**Q3: At which OSI layer does a firewall operate?**
A: Traditional stateless packet-filtering firewalls operate at Layer 3/4 (IP and port based rules). Next-gen firewalls (NGFW) and WAFs inspect up to Layer 7 (application content).

**Q4: Where would you place a switch and a router in the OSI model?**
A: A switch operates at Layer 2 (uses MAC addresses to forward frames within a LAN). A router operates at Layer 3 (uses IP addresses to route packets between networks).

---

## 2. TCP vs UDP & the Three-Way Handshake

### Notes
- **TCP (Transmission Control Protocol):** Connection-oriented, reliable, ordered delivery, error-checked. Used where accuracy matters (HTTP, HTTPS, FTP, SSH, email).
- **UDP (User Datagram Protocol):** Connectionless, no guarantee of delivery/order, faster, lower overhead. Used where speed matters more than reliability (DNS queries, video streaming, VoIP, DHCP).
- **Three-way handshake (TCP connection setup):**
  1. Client sends **SYN**
  2. Server responds **SYN-ACK**
  3. Client responds **ACK**
  - Connection termination normally uses a **four-way handshake**: FIN, ACK, FIN, ACK.

### Interview Q&A
**Q1: Explain the TCP three-way handshake.**
A: It's how a TCP connection is established. The client sends a SYN packet to request a connection. The server replies with a SYN-ACK, acknowledging the request and sending its own synchronization. The client then sends an ACK to confirm, and the connection is fully established. This ensures both sides agree on initial sequence numbers before data flows.

**Q2: What is a SYN flood attack and how does it relate to the handshake?**
A: An attacker sends a large volume of SYN packets, often with spoofed source IPs, and never completes the handshake with the final ACK. The server keeps "half-open" connections in memory waiting for the ACK, exhausting its connection table and causing denial of service. Defenses include SYN cookies, rate limiting, and firewalls that track connection state.

**Q3: TCP vs UDP — when would you use each, and why does it matter for security monitoring?**
A: TCP is reliable and connection-oriented — good for web traffic, email, file transfer where data integrity matters. UDP is fast but unreliable — used for DNS, streaming, VoIP. For security monitoring, UDP-based protocols like DNS are commonly abused for exfiltration or C2 tunneling (DNS tunneling) since UDP has no handshake to inspect, making anomaly-based detection more important there.

**Q4: What's the difference between TCP flags SYN, ACK, FIN, and RST?**
A: SYN initiates a connection, ACK acknowledges received data/requests, FIN gracefully closes a connection, and RST abruptly resets/terminates a connection (often seen when a port is closed or a connection is forcibly dropped — useful in port scan detection).

---

## 3. IP Addressing & Subnetting

### Notes
- **IPv4:** 32-bit address, written as 4 octets (e.g., 192.168.1.1). Classes A/B/C historically, but **CIDR (Classless Inter-Domain Routing)** notation (e.g., /24) is now standard.
- **Private IP ranges:** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — not routable on the public internet.
- **Subnet mask:** Divides an IP into network and host portions. /24 = 255.255.255.0 = 256 addresses (254 usable).
- **Subnetting purpose in security:** network segmentation limits blast radius of a breach, separates sensitive zones (e.g., DMZ, server VLAN, guest Wi-Fi).
- **IPv6:** 128-bit address, designed to solve IPv4 exhaustion; no need for NAT; has built-in support for IPSec.

### Interview Q&A
**Q1: What is CIDR notation and why is it used?**
A: CIDR (e.g., 192.168.1.0/24) specifies how many bits of an IP address represent the network portion. It replaced the rigid Class A/B/C system, allowing flexible, efficient allocation of IP address space instead of wasting large blocks.

**Q2: How would you calculate the number of usable hosts in a /26 subnet?**
A: /26 leaves 32-26 = 6 host bits → 2^6 = 64 total addresses, minus 2 (network address and broadcast address) = **62 usable hosts**.

**Q3: Why is network segmentation/subnetting important from a security standpoint?**
A: It limits lateral movement. If an attacker compromises a machine in one subnet (e.g., guest Wi-Fi), proper segmentation with firewall/ACL rules between subnets prevents them from directly reaching sensitive subnets like finance servers or domain controllers. This is a core part of defense-in-depth and Zero Trust design.

**Q4: What's the difference between a public and a private IP address?**
A: Public IPs are globally unique and routable on the internet, assigned by ISPs/IANA. Private IPs (RFC 1918 ranges) are only valid within a local network and require NAT to communicate externally — they add a layer of obscurity since they aren't directly reachable from outside.

**Q5: Why is IPv4 exhaustion relevant, and how does IPv6 change the security landscape?**
A: IPv4's ~4.3 billion addresses ran out, forcing widespread NAT use. IPv6 gives every device a unique public-style address, removing NAT's implicit "hiding" effect — meaning host-based firewalls and proper access controls matter even more, since devices are more directly reachable.

---

## 4. DNS (Domain Name System)

### Notes
- Translates human-readable domain names into IP addresses.
- Resolution flow: Browser cache → OS cache → Resolver (ISP/recursive) → Root server → TLD server → Authoritative server → IP returned.
- Common DNS record types: **A** (IPv4), **AAAA** (IPv6), **MX** (mail server), **CNAME** (alias), **TXT** (verification/SPF/DKIM), **NS** (nameserver).
- Security relevance: DNS is a top attack surface — DNS spoofing/cache poisoning, DNS tunneling (data exfiltration/C2 over DNS queries), DNS hijacking, DGA (domain generation algorithms) used by malware.

### Interview Q&A
**Q1: Walk me through what happens when you type a URL into a browser (DNS portion).**
A: The browser first checks its own cache, then the OS cache. If not found, it queries a configured DNS resolver (recursive resolver), which — if it doesn't have it cached — queries a root server, which points to the TLD server (e.g., .com), which points to the authoritative name server for the domain, which finally returns the IP address. This IP is then used to establish a TCP connection.

**Q2: What is DNS cache poisoning?**
A: An attacker injects a fake DNS response into a resolver's cache, causing it to return a malicious IP address for a legitimate domain. Victims querying that domain get redirected to an attacker-controlled server — often used for phishing or malware distribution. Defenses include DNSSEC, source port randomization, and using trusted resolvers.

**Q3: What is DNS tunneling and why is it a concern for a SOC?**
A: DNS tunneling encodes data (commands or exfiltrated data) inside DNS queries/responses, since DNS traffic (UDP/53) is almost always allowed through firewalls. It's used for covert command-and-control or data exfiltration. Detection relies on spotting anomalies: unusually long subdomains, high query volume to a single domain, or non-standard record types.

**Q4: What's the difference between a recursive and an authoritative DNS server?**
A: A recursive resolver does the legwork of querying multiple servers on behalf of a client to resolve a name. An authoritative server holds the actual DNS records for a domain and gives the definitive answer once queried.

---

## 5. DHCP (Dynamic Host Configuration Protocol)

### Notes
- Automatically assigns IP addresses, subnet mask, gateway, and DNS servers to devices on a network.
- Process = **DORA**: **D**iscover → **O**ffer → **R**equest → **A**cknowledge.
- Security relevance: **Rogue DHCP servers** can hand out malicious gateway/DNS info to redirect traffic (a MITM technique); **DHCP starvation** attacks exhaust the address pool (DoS).

### Interview Q&A
**Q1: Explain the DHCP DORA process.**
A: The client broadcasts a **Discover** message looking for a DHCP server. Available servers respond with an **Offer** containing a candidate IP. The client broadcasts a **Request** accepting one offer. The server sends an **Acknowledge (ACK)**, finalizing the lease with IP, subnet, gateway, and DNS info.

**Q2: What is a rogue DHCP server attack and how would you defend against it?**
A: An attacker sets up an unauthorized DHCP server on the network that races legitimate offers, handing out a malicious default gateway or DNS server to victims, enabling man-in-the-middle attacks. Defense: DHCP snooping on switches, which only allows DHCP responses from trusted, configured ports.

---

## 6. ARP (Address Resolution Protocol)

### Notes
- Maps IP addresses (Layer 3) to MAC addresses (Layer 2) within a local network.
- Devices maintain an **ARP cache/table**.
- **ARP Spoofing/Poisoning:** attacker sends forged ARP replies to associate their MAC with another device's IP (often the gateway), enabling MITM or traffic interception — classic entry-level attack demo in interviews/labs.

### Interview Q&A
**Q1: What is ARP and why is it needed?**
A: ARP resolves a known IP address to the corresponding MAC address so devices on the same LAN segment can actually deliver Ethernet frames to each other, since Layer 2 switching uses MAC addresses, not IPs.

**Q2: Explain ARP spoofing/poisoning and its impact.**
A: The attacker sends unsolicited, forged ARP replies claiming to own the IP of a legitimate host (often the default gateway). Victim machines update their ARP cache with the attacker's MAC address, so traffic meant for the gateway is instead sent to the attacker, enabling eavesdropping or a full man-in-the-middle attack. Mitigations: dynamic ARP inspection (DAI) on switches, static ARP entries for critical devices, and encryption (so intercepted traffic is still unreadable).

---

## 7. HTTP, HTTPS, SSL/TLS

### Notes
- **HTTP:** stateless application-layer protocol for transferring web content; plaintext by default (port 80).
- **HTTPS:** HTTP secured by SSL/TLS (port 443); encrypts data in transit, verifies server identity via certificates.
- **SSL** is the older, deprecated standard; **TLS** is its modern successor (TLS 1.2/1.3 in current use).
- **TLS Handshake (simplified):** Client Hello → Server Hello + Certificate → Key exchange → Both derive session key → Encrypted communication begins.
- Certificates are issued by **CAs (Certificate Authorities)**; browsers validate the chain of trust.

### Interview Q&A
**Q1: What's the difference between SSL and TLS?**
A: TLS is the modern, more secure successor to SSL. SSL (versions 1–3) has known vulnerabilities and is deprecated; TLS (1.2 and especially 1.3) is what's used today. People still colloquially say "SSL certificate" even though it's technically a TLS certificate.

**Q2: Briefly explain what happens during a TLS handshake.**
A: The client sends a "Client Hello" listing supported cipher suites and TLS versions. The server responds with its certificate and chosen cipher suite. The client verifies the certificate against a trusted CA, then a key exchange (e.g., via Diffie-Hellman) happens to derive a shared session key. Once both sides have the session key, all further communication is symmetrically encrypted for speed.

**Q3: Why is HTTPS important, and what does it actually protect against?**
A: HTTPS encrypts data in transit (confidentiality), verifies the server's identity via its certificate (authentication), and ensures data isn't tampered with in transit (integrity). It protects against eavesdropping and man-in-the-middle attacks on the network path — but it does **not** protect against server-side vulnerabilities like SQL injection or a compromised backend.

**Q4: What happens if a certificate is expired or self-signed — is the connection insecure?**
A: The browser will warn or block the connection because trust cannot be established. The traffic could still be technically encrypted, but you can't verify you're actually talking to the legitimate server — so it's unsafe against MITM, since an attacker could present their own self-signed cert.

---

## 8. Ports & Common Protocols

### Notes
| Port | Protocol | Use |
|---|---|---|
| 20/21 | FTP | File transfer (unencrypted) |
| 22 | SSH | Secure remote login |
| 23 | Telnet | Remote login (unencrypted — avoid) |
| 25 | SMTP | Sending email |
| 53 | DNS | Name resolution |
| 67/68 | DHCP | IP assignment |
| 80 | HTTP | Web traffic (unencrypted) |
| 110 | POP3 | Email retrieval |
| 143 | IMAP | Email retrieval (syncs across devices) |
| 443 | HTTPS | Encrypted web traffic |
| 3389 | RDP | Remote Desktop |
| 3306 | MySQL | Database |

### Interview Q&A
**Q1: Why is Telnet considered insecure compared to SSH?**
A: Telnet transmits all data, including credentials, in plaintext, so anyone sniffing the network can read login credentials and commands. SSH encrypts the entire session, protecting confidentiality and integrity, so it has effectively replaced Telnet for remote administration.

**Q2: If you saw traffic on port 3389 from an unusual external IP, what would that flag as?**
A: Port 3389 is RDP (Remote Desktop Protocol). Unexpected external RDP traffic is a major red flag — it's one of the most common initial-access vectors for ransomware groups (brute-forcing or using leaked credentials against exposed RDP). It would warrant investigating whether RDP is meant to be internet-facing, checking for brute-force login attempts, and confirming MFA is in place.

**Q3: What's the difference between well-known ports, registered ports, and dynamic/private ports?**
A: Well-known ports (0–1023) are reserved for standard services (HTTP=80, SSH=22). Registered ports (1024–49151) are assigned to specific applications by IANA but not as strictly controlled. Dynamic/private ports (49152–65535) are used ephemerally, e.g., as the client-side source port for outbound connections.

---

## 9. Network Devices: Hub, Switch, Router, Firewall (Basics)

### Notes
- **Hub:** Layer 1, broadcasts data to all ports — no intelligence, insecure, obsolete.
- **Switch:** Layer 2, uses MAC address table to send frames only to the intended port — reduces collisions, improves performance.
- **Router:** Layer 3, connects different networks, routes packets based on IP address, uses routing tables.
- **Firewall:** Filters traffic based on rules (covered in depth in Part 2).
- **VLAN (Virtual LAN):** Logically segments a physical switch into multiple broadcast domains — used for security segmentation without needing separate physical hardware.

### Interview Q&A
**Q1: What's the difference between a hub and a switch?**
A: A hub broadcasts every incoming packet to all connected devices regardless of destination, which is inefficient and insecure (anyone can sniff all traffic). A switch learns MAC addresses and forwards frames only to the specific port the destination device is on, improving both performance and security.

**Q2: What is a VLAN and why would a security team use one?**
A: A VLAN logically separates devices into different broadcast domains on the same physical switch hardware. Security teams use VLANs to isolate traffic — e.g., putting IoT devices, guest Wi-Fi, and finance servers on separate VLANs — so that even if one segment is compromised, an attacker can't freely reach others without crossing a routed/firewalled boundary.

**Q3: How does a router decide where to send a packet?**
A: It checks the destination IP address against its routing table and forwards the packet out the appropriate interface toward the next hop, based on the longest prefix match (most specific matching route).

---

## 10. NAT (Network Address Translation)

### Notes
- Translates private IP addresses to a public IP (and back) so multiple internal devices can share one public IP for internet access.
- Types: **Static NAT** (1:1 mapping), **Dynamic NAT** (pool of public IPs), **PAT/NAT Overload** (many private IPs share one public IP, differentiated by port — most common in home/office routers).
- Security benefit: internal IP addressing scheme is hidden from the internet, adding a layer of obscurity (not a substitute for a firewall).

### Interview Q&A
**Q1: What is NAT and why is it used?**
A: NAT translates private internal IP addresses to a public IP address (and vice versa) so devices on a private network can access the internet while sharing a limited number of public IPs. It was largely driven by IPv4 address exhaustion.

**Q2: Is NAT a security control?**
A: NAT provides a side benefit of obscuring internal IP addressing since internal hosts aren't directly addressable from the internet, but it is **not** a substitute for a firewall — it doesn't inspect or block traffic based on security policy. A firewall is still required for real access control.

---

## Quick Revision — Rapid Fire (Part 1)

1. **Q:** What layer does IP operate at? **A:** Layer 3 (Network).
2. **Q:** What layer does TCP operate at? **A:** Layer 4 (Transport).
3. **Q:** Which is faster, TCP or UDP, and why? **A:** UDP — no handshake or acknowledgment overhead.
4. **Q:** Default port for HTTPS? **A:** 443.
5. **Q:** What does DNS record type "MX" specify? **A:** Mail server for the domain.
6. **Q:** What is the broadcast address in a /24 subnet 192.168.1.0? **A:** 192.168.1.255.
7. **Q:** What protocol resolves IP to MAC? **A:** ARP.
8. **Q:** What replaces the deprecated SSL protocol? **A:** TLS.
9. **Q:** What does DORA stand for in DHCP? **A:** Discover, Offer, Request, Acknowledge.
10. **Q:** Which device operates using MAC address tables? **A:** Switch.

---

**Next:** *Part 2 — Security-Applied Networking* covers Firewalls (stateful/stateless), IDS/IPS, VPNs, wireless security, network-based attacks (DDoS, MITM, spoofing), packet analysis/Wireshark, Zero Trust, and cloud networking security — say the word and I'll build that one too.
