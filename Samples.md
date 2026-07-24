
### **ORB Malware Samples**

This file provides a technical catalog of the binaries, scripts, and certificates used by China-nexus threat actors to facilitate operational relay box (ORB) activities.

| Malware Family / Cluster | Filename / Identifier | Hash Type | Hash Value | Source Report |
| :--- | :--- | :--- | :--- | :--- |
| **Bulbature** | bulbature | SHA-256 | `41e189a5b68f305ab6251a06475b76777bda0d035ea06cd569306ed5c98bdc98` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **GobRAT** | zone.arm | SHA-256 | `48b243fd7ed8bc0b7ce663f0b3fc34f07fcf9fb04bf8bceaff8b7453ab4e5318` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **GobRAT** | zone.x86_64 | SHA-256 | `91eaa94223c12ddc89eca5220a8c57f0254f587f73c9edc161fc161a56e2c2f0` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **GobRAT** | zone.i686 | SHA-256 | `b1c21264a60edb64895c8c61507211a829f13068541f875b615e6c1c363122ba` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **GobRAT** | zone.mips | SHA-256 | `726ac8f88c4585ccb2ce2e3325726230dc7bd2c7f6667085ac2f665c4ce3fb46` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **TINYSHELL (UNC3886)** | appid | SHA-256 | `98380ec6bf4e03d3ff490cdc6c48c37714450930e4adf82e6e14d244d8373888` | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) |
| **TINYSHELL (UNC3886)** | irad | SHA-256 | `5bef7608d66112315eefff354dae42f49178b7498f994a728ae6203a8a59f5a2` | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) |
| **TINYSHELL (UNC3886)** | jdosd | SHA-256 | `c0ec15e08b4fb3730c5695fb7b4a6b85f7fe341282ad469e4e141c40ead310c3` | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) |
| **TINYSHELL (UNC3886)** | lmpad | SHA-256 | `5995aaff5a047565c0d7fe3c80fa354c40e7e8c3e7d4df292316c8472d4ac67a` | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) |
| **TINYSHELL (UNC3886)** | oemd | SHA-256 | `905b18d5df58dd6c16930e318d9574a2ad793ec993ad2f68bca813574e3d854b` | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) |
| **TINYSHELL (UNC3886)** | to | SHA-256 | `e1de05a2832437ab70d36c4c05b43c4a57f856289224bbd41182deea978400ed` | [Google/Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) |
| **ShortLeash (LapDogs)** | ShortLeash Linux | SHA-256 | `9b954bfc2949d07eb41446225592eaa65ed3954cd2b93a13c574bb89147a4465` | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2025/06/LapDogs-STRIKE-Report-June-2025.pdf) |
| **ShortLeash (LapDogs)** | ShortLeash Linux | SHA-256 | `33ff77940436498a50bbb05391324964063cd3c93f2e66b07d1cb31442bb1513` | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2025/06/LapDogs-STRIKE-Report-June-2025.pdf) |
| **ShortLeash (LapDogs)** | ShortLeash Windows | SHA-256 | `02ab315e4e3cf71c1632c91d4914c21b9f6e0b9aa0263f2400d6381aab759a61` | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2025/06/LapDogs-STRIKE-Report-June-2025.pdf) |
| **PolarEdge** | cipher_log | SHA-256 | `eda7cc5e1781c681afe99bf513fcaf5ae86afbf1d84dfd23aa563b1a043cbba8` | [Sekoia](https://www.sekoia.com/blog/polaredge-unveiling-an-uncovered-iot-botnet) |
| **PolarEdge (Asus)** | sshd_sftp | SHA-256 | `13cd040a7f488e937b1b234d71a0126b7bc74367bf6538b6961c476f5d620d13` | [Sekoia](https://www.sekoia.com/blog/polaredge-unveiling-an-uncovered-iot-botnet) |
| **PolarEdge (QNAP)** | QTS.install.ssl | SHA-256 | `464f29d5f496b4acffc455330f00adb34ab920c66ca1908eee262339d6946bcd` | [Sekoia](https://www.sekoia.com/blog/polaredge-unveiling-an-uncovered-iot-botnet) |
| **PolarEdge (Synology)**| hdparmd | SHA-256 | `932b2545bd6e3ad74b82ca2199944edecf9c92ad3f75fce0d07e04ab084824d5` | [Sekoia](https://www.sekoia.com/blog/polaredge-unveiling-an-uncovered-iot-botnet) |
| **RPX Server** | server_multi | SHA-256 | `827797a9bff728ae6f46abd505e67a15e40b0ba69a8dc92a36fd90d9974c9593` | [Censys](https://censys.com/blog/a-look-at-polaredge-adjacent-infrastructure) |
| **Pakedge (APT31)** | ORB implant | MD5 | `77c73b8b1846652307862dd66ec09ebf` | [Sekoia](https://blog.sekoia.io/walking-on-apt31-infrastructure-footprints/) |
| **Tiny Shell (APT31)** | unifi-video | MD5 | `4640805c362b1e5bee5312514dd0ab2b` | [Sekoia](https://blog.sekoia.io/walking-on-apt31-infrastructure-footprints/) |
| **WrtHug** | TLS Certificate | SHA-1 | `1894a6800dff523894eba7f31cea8d05d51032b4` | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2026/05/STRIKE_Asus_WrtHug-Report_V7.pdf) |
| **GobRAT** | zoneupdate.sh | SHA-256 | `0858c36ed2cf29d9f7de3d7b8d595e45d888da422e76bc9c9115a8f25027d5e7` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **GobRAT** | zonesetup.sh | SHA-256 | `6632fe263bf687fb8d46dd29eaf90601350681aa1930a14e2aba2a16f6c3e040` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **GobRAT** | hold_by_bot.sh | SHA-256 | `869a6cd8205af5ec1bf04e6abf0ff79f12e62a8eeae129b9e219e1179520bac3` | [Sekoia](https://www.sekoia.com/blog/bulbature-beneath-the-waves-of-gobrat) |
| **LapDogs** | Bash startup script | SHA-256 | `75618401b64046d970df49fcfdfcc36174b0aae27ac4e1c178dc75219992080a` | [SecurityScorecard](https://securityscorecard.com/wp-content/uploads/2025/06/LapDogs-STRIKE-Report-June-2025.pdf) |
| **UAT-7810 (LapDogs)** | **LEASHTEST** (iot-test) | SHA-256 | `1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823` | [Cisco Talos](https://blog.talosintelligence.com/uat-7810/) |
| **UAT-7810 (LapDogs)** | **LONGLEASH** (ff-agent / nz1.0) | SHA-256 | `755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f` | [Cisco Talos](https://blog.talosintelligence.com/uat-7810/) |
| **UAT-7810 (LapDogs)** | **DOGLEASH** | SHA-256 | `dc4f25b2247cfdd6fc96848db30a178baa4419a4c854e86e315b465836102d14` | [Cisco Talos](https://blog.talosintelligence.com/uat-7810/) |
| **UAT-7810 (LapDogs)** | **DOGLEASH** | SHA-256 | `ac8eae94d27122f4751bc96d9ea52d30000b7ca37569a2291b2710824ca3396f` | [Cisco Talos](https://blog.talosintelligence.com/uat-7810/) |
| **UAT-7810 (LapDogs)** | **DOGLEASH** | SHA-256 | `425bf771c8c9f740b1ae9803dcb4fd45af4d6a6f171fcc72fc7d511095ca82ce` | [Cisco Talos](https://blog.talosintelligence.com/uat-7810/) |
| **GOREshell (Windows)** | `glib-2.0.dll` | SHA-1 | `cb2d18fb91f0cd88e82cb36b614cfedf3e4ae49b` | [SentinelOne](https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/) |
| **GOREshell (Linux)** | `snapd` | SHA-1 | `411180c89953ab5e0c59bd4b835eef740b550823` | [SentinelOne](https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/) |
| **GOREshell (Linux)** | `update-notifier` | SHA-1 | `7dabf87617d646a9ec3e135b5f0e5edae50cd3b9` | [SentinelOne](https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/) |
| **PurpleHaze Webshell**| `a.php` | SHA-1 | `106248206f1c995a76058999ccd6a6d0f420461e` | [SentinelOne](https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/) |
