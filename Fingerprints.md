### **Fingerprints**

Based on open source reporting, here is the technical data for the network indicators used to identify and track China-nexus Operational Relay Box (ORB) networks, broken down into multiple categories.

---

#### **Table 1: JARM Fingerprints**
These fingerprints identify the specific TLS server configuration used by the malicious services, often revealing similarities in the underlying web server software.

| Cluster / Malware | JARM Fingerprint | Context | Source |
| :--- | :--- | :--- | :--- |
| **LapDogs** | `3fd3fd16d3fd3fd22c3fd3fd3fd3fdf20014c17cd0943e6d9e2fb9cd59862b` | Identifies the ShortLeash backdoor service; indicative of lightweight web servers. | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2025/06/LapDogs-STRIKE-Report-June-2025.pdf) |
| **PolarEdge** | `3fd3fd16d3fd3fd22c3fd3fd3fd3fdf20014c17cd0943e6d9e2fb9cd59862b` | Shared with LapDogs, identifying similar lightweight web server configurations. | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2025/06/LapDogs-STRIKE-Report-June-2025.pdf) |
| **ViciousTrap** | `29d3fd00029d29d00029d3fd29d29dfff2e71077958c8b453cd71f499e9b99` | A unique JARM used to identify over 5,300 compromised hosts. | [Sekoia](https://www.sekoia.com/blog/vicioustrap-infiltrate-control-lure-turning-edge-devices-into-honeypots-en-masse) |

---

#### **Table 2: X.509 Certificate Attributes**
The following certificate metadata attributes and hashes are used to identify ORB servers and devices.

| Cluster / Malware | Subject and Issuer Attributes | Hash / Thumbprint | Source |
| :--- | :--- | :--- | :--- |
| **LapDogs** | `CN=ROOT, O=LAPD, ST=California, C=US, L=LA, OU=Police department` | `7267c503291cd69efe109a32f5ef090f73268353` | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2025/06/LapDogs-STRIKE-Report-June-2025.pdf) |
| **WrtHug** | `CN=a, OU=a, O=a, L=a, ST=a, C=aa` | SHA-1: `1894a6800dff523894eba7f31cea8d05d51032b4` | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2026/05/STRIKE_Asus_WrtHug-Report_V7.pdf) |
| **PolarEdge** | `Issuer: C=NL, O=PolarSSL, CN=Polarssl Test EC CA`; `Subject: C=NL, O=PolarSSL, CN=localhost` | SHA-256: `e234e102cd8de90e258906d253157aeb7699a3c6df0c4e79e05d01801999dcb5` | [Censys](https://censys.com/blog/a-look-at-polaredge-adjacent-infrastructure) |
| **GobRAT** | `C=AU, ST=Some-State, O=Internet Widgits Pty Ltd` | MD5: `af4ad0bd9221ffc63ae5acff4034834a` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **GobRAT (Alt)** | `O=mkcert development certificate, OU=a@a-virtual-machine` | MD5: `e4b7b3a2610ad706a83667a5bac7cd31` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **ViciousTrap** |  | SHA-1: `c15f77d64b7bbfb37f00ece5a62095562b37dec4` | [Sekoia](https://www.sekoia.com/blog/vicioustrap-infiltrate-control-lure-turning-edge-devices-into-honeypots-en-masse) |

---

#### **Table 3: Open Ports and Port Banners**
Banners and specific port assignments provide behavioral fingerprints for automated scanning and identification of infected devices.

| Cluster / Malware | Port(s) | Banner / Response / Behaviour | Source |
| :--- | :--- | :--- | :--- |
| **Quad7 (xlogin)** | `7777 (TCP)` | `xlogin:` | [Team Cymru](https://www.team-cymru.com/post/botnet-7777-are-you-betting-on-a-compromised-router) |
| **Quad7 (alogin)** | `63256 (TCP)` | `alogin:` | [Team Cymru](https://www.team-cymru.com/post/botnet-7777-are-you-betting-on-a-compromised-router) |
| **Quad7 (SOCKS5)** | `11288 (TCP)` | `\x05\xff` | [Team Cymru](https://www.team-cymru.com/post/botnet-7777-are-you-betting-on-a-compromised-router) |
| **Quad7 (rlogin)** | `63210 (TCP)` | Password prompt (targeted at Ruckus Wireless). | [Sekoia](https://blog.sekoia.io/a-glimpse-into-the-quad7-operators-next-moves-and-associated-botnets/) |
| **LapDogs** | Various assigned ports | Versionless **Nginx** (simulated). | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2025/06/LapDogs-STRIKE-Report-June-2025.pdf) |
| **AyySSHush** | `53282 (TCP)` | SSH-2.0-dropbear (persistent remote access). | [GreyNoise Labs](https://www.labs.greynoise.io/grimoire/2025-03-28-ayysshush/) |
| **GobRAT Admin** | `52208`, `42208`, etc. | `{"message": "need login", "success":0}` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **JDY (Expanded)** | `13339 (TCP)` | **Platypus** server banner (Termite clients). | [Lumen](https://www.lumen.com/blog/en-us/expanded-jdy-iot-and-soho-botnet-enables-rapid-vulnerability-exploitation) |
| **ViciousTrap** | `80`, `8000`, `8080` | N/A (Characterized by fixed **TCP window size 64240**). | [Sekoia](https://www.sekoia.com/blog/vicioustrap-infiltrate-control-lure-turning-edge-devices-into-honeypots-en-masse) |
| **UNC3886 (irad)** | `31234 (TCP)` | Passive mode listener (post-ICMP activation). | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) |
| **UNC3886 (jdosd)** | `33512 (UDP)` | Encrypted beacon (responds with PID). | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) |
| **ZuoRAT** | `48101` | Mutex listener (ensures single execution). | [Lumen](https://www.lumen.com/blog/en-us/zuorat-hijacks-soho-routers-silently-stalk-networks) |
