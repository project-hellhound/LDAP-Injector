<p align="center">
  <img src="Image/banner.jpg" alt="Agent389 Banner" width="800">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue.svg?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/License-GPL--3.0-green.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Python-3.7+-blue.svg?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg?style=flat-square" alt="Platform">
</p>

<h1 align="center">Agent389</h1>

<p align="center">
  <b>Agent389</b> is a professional, high-fidelity LDAP injection and enumeration engine designed for autonomous vulnerability research and exploitation. Inspired by the precision and lethality of tactical operations, Agent389 implements a multi-signal detection pipeline to uncover deep-seated directory service flaws while maintaining full operational stealth.
</p>

---

## Tactical Overview

Agent389 addresses the complexity of modern LDAP-backed web applications by implementing an advanced detection pipeline. Unlike traditional scanners, Agent389 correlates timing differentials, boolean response shifts, and out-of-band signals to build a deterministic proof of vulnerability.

### Key Capabilities

- **Autonomous Parameter Discovery**: Intelligent crawler that identifies hidden input vectors, including JSON keys, form fields, and URI fragments.
- **Polymorphic WAF Evasion**: Real-time mutation of injection strings to bypass signature-based and heuristic filtering layers.
- **Three-Stage Verification**: Automated proof-of-concept generation that confirms exploitability through differential analysis.
- **Directory Schema Fingerprinting**: Passive and active probing to identify backend directory types (Active Directory, OpenLDAP, 389 Directory Server).
- **Adaptive Rate Control**: Dynamic request throttling to ensure target stability and bypass rate-limiting defenses.

---

## Technical Specifications

Agent389 is structured as a modular tactical suite, allowing for granular control over the scanning lifecycle:

| Module | Functional Responsibility |
| :--- | :--- |
| **Engine** | Core orchestration of phase-based injection and state management. |
| **Discovery** | Surface area mapping and recursive parameter identification. |
| **Detection** | Multi-vector analysis pipeline (Timing, Boolean, Error, OOB). |
| **Extraction** | High-speed data exfiltration engine for blind LDAP enumeration. |
| **Intelligence** | Stateful memory system for payload optimization and WAF adaptation. |

---

## Operational Deployment

### Initial Setup

To deploy Agent389 in your environment, utilize the integrated professional installer:

```bash
git clone https://github.com/project-hellhound-org/Agent389.git
cd Agent389
chmod +x install.sh
./install.sh
```

### Standard Execution

Run a tactical scan against a target environment:

```bash
agent389 https://target-app.internal --threads 10 --budget 1000
```

---

## Contributors

- **Abinav3ac** (Lead Contributor & Architect)

See the full list of [Contributors](CONTRIBUTORS.md).

---

## Author & License

- **Author**: Abinav3ac
- **License**: Distributed under the GNU General Public License v3.0. See `LICENSE` for details.

---

<p align="center">
  <b>Project Hellhound Tactical Unit</b>
</p>
