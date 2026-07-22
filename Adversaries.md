### **Adversaries**

This file tracks the relationship between known threat groups and the ORB networks they utilize to mask their operational activity and maintain persistence.

| Named Threat Group | Associated ORB Network / Cluster | Role & Context |
| :--- | :--- | :--- |
| **UNC2630** (APT5) | **SPACEHOP** (ORB3) | A cluster with suspected links to APT5 that used SPACEHOP nodes to exploit vulnerabilities like CVE-2022-27518 in Citrix ADC and Citrix Gateway for initial access. |
| **APT15** (Ke3Chang, Nylon Typhoon) | **SPACEHOP** (ORB3) | A China-nexus threat actor that leases access to the SPACEHOP provisioned VPS network to conduct reconnaissance and exploitation. |
| **APT15** (Ke3Chang, Nylon Typhoon) | **PurpleHaze** | SentinelOne tracks the PurpleHaze network as an infrastructure cluster operated from China and actively shared among several suspected Chinese cyberespionage actors. |
| **UNC5174** | **PurpleHaze** | UNC5174 is a suspected Chinese MSS contractor and initial access broker; specializes in rapid vulnerability weaponization. |
| **APT31** (Zirconium, Violet Typhoon, JUDGMENT PANDA) | **FLORAHOX** (ORB2), **PakEdge** | FLORAHOX is an example of both a non-provisioned and a hybrid ORB network. It is composed of an adversary-controlled operations servers (ACOS) node, compromised network router and IoT devices, and leased VPS servers that interface with a customized TOR relay network layer. The network is used to proxy traffic from a source and relay it through a TOR network and several compromised router nodes to obfuscate the source of the traffic. It is believed to be used in cyber espionage campaigns by a diverse set of China-nexus threat actors. |
| **Silk Typhoon** (MURKY PANDA) | **ORB28** | A China-nexus adversary whose activities align with MURKY PANDA, focusing on intelligence collection through advanced cloud-conscious tradecraft. They focused on targeting Microsoft 365 accounts. |
| **UNC3886** | **GOBRAT**, **Juniper Infrastructure** | A highly adept China-nexus group that utilizes GOBRAT staging nodes as part of its operations to maintain stealthy access to telecommunications and internal networks. |
| **Volt Typhoon** (Bronze Silhouette) | **KV-botnet**, **JDY botnet** | A state-sponsored actor based in China that uses these clusters for surreptitious tunnels and reconnaissance scanning targeting critical infrastructure. |
| **UAT-5918** | **LapDogs** | A China-nexus espionage actor assessed to have used the LapDogs ORB at least once in its operations targeting critical infrastructure in Taiwan. |
| **UAT-7810** | **LapDogs** | The China-nexus threat actor responsible for LapDogs, who is tasked with establishing Operational Relay Box (ORB) networks that can then be leveraged by associated secondary threat actors to conduct their own malicious attacks against high value targets. |
| **Flax Typhoon** (ETHEREAL PANDA) | **Sparrow** | A massive network of over 260,000 compromised devices managed by the PRC-based Integrity Technology Group using a custom application called "Sparrow" to facilitate DDoS attacks and cyber espionage operations | 
| **Weaver Ant** | **Unnamed ORB network** | Compromises Zyxel routers operated by SE Asian telecoms to proxy traffic and pivot between different providers to conceal infrastructure. | [Sygnia](https://www.sygnia.co/threat-reports-and-advisories/weaver-ant-tracking-a-china-nexus-cyber-espionage-operation/) |
