### **Components**

This file details the publicly available software, communication protocols, and administrative tools co-opted by threat actors to build and manage ORB infrastructure.

| Open Source Tool | Function / Purpose | Associated ORB or Adversary | Context of Use |
| :--- | :--- | :--- | :--- |
| [**TinyShell (tsh)**](https://github.com/creaktive/tsh) | Lightweight C-based backdoor. | **UNC3886**, **APT31** | Used as a foundational backdoor for multiple customized implants on Juniper Implants and Pakedge infrastructure. |
| [**frp (Fast Reverse Proxy)**](https://github.com/fatedier/frp) | Reverse proxy for traversing firewalls. | **GobRAT / Bulbature** | Included in staging server scripts to establish tunnels between compromised edge devices and C2 servers. |
| [**Platypus**](https://github.com/WangYihang/Platypus) | Reverse shell and host management tool. | **JDY botnet** (Volt Typhoon) | Used to manage victim devices; a Platypus server was identified on a JDY payload server on port 13339. |
| [**Neo-reGeorg**](https://github.com/L-codes/Neo-reGeorg) | Advanced ASPX/PHP/JSP web shell. | **MURKY PANDA** (Silk Typhoon) | Deployed on internet-facing appliances to establish initial access and persistence. |
| [**Go-Shadowsocks2**](https://github.com/shadowsocks/go-shadowsocks2) | Secure SOCKS5 proxy using Shadowsocks. | **RPX / PolarEdge Adjacent** | Identified in open directories on servers associated with the management of proxy nodes. |
| [**Clash Proxy**](https://en.clash.wiki/) | Rule-based tunnel in Go. | **RPX / PolarEdge Adjacent** | Configuration files (`clash.yaml`) were found being used to manage upstream SOCKS5 servers for proxy nodes. |
| [**KCP**](https://github.com/skywind3000/kcp) | Low-latency, high-bandwidth UDP protocol. | **Quad7 (FsyNet)** | Used as the communication protocol for the "FsyNet" project to relay attacks and obfuscate traffic. |
| [**CJDNS (cjdroute2)**](https://github.com/cjdelisle/cjdns/blob/master/client/cjdroute2.c) | Encrypted IPv6 network using public-key cryptography. | **Quad7 (Netd)** | Leveraged by the "netd" binary to create secure, independent communication tunnels between ORBs and C2 servers. |
| [**BusyBox**](https://github.com/mirror/busybox) | Multi-call binary for embedded systems. | **JDY botnet**, **ViciousTrap** | Commonly used in dropper scripts to provide necessary utilities (e.g., `wget`, `ftpget`) on minimal firmware environments. |
| [**Mbed TLS (PolarSSL)**](https://github.com/Mbed-TLS/mbedtls) | Lightweight cryptographic library. | **PolarEdge**, **Bulbature** | Statically compiled into backdoors for custom TLS encryption and certificate management. |
| [**libcurl**](https://curl.se/libcurl/) | Client-side URL transfer library. | **Quad7 (UPDTAE)** | Statically linked into reverse shells to facilitate HTTP-based beaconing every 30 seconds. |
| [**Garble**](https://github.com/burrowers/garble) | Go code obfuscator. | **MURKY PANDA** | Used to obfuscate the *CloudedHope* RAT to hinder static analysis and detection. |
| [**wzshiming/sshd**](https://github.com/wzshiming/sshd) | Go-based SSH server project. | **UNC3886** | Leveraged as the base for custom SSH servers used to hijack legitimate authentications. |
