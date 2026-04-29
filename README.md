<p align="center">
  <img src="Image/banner.png" alt="DNwatch Banner" width="800">
</p>

<p align="center">
  <a href="https://github.com/project-hellhound-org/DNwatch/releases"><img src="https://img.shields.io/github/v/release/project-hellhound-org/DNwatch?color=blue&style=for-the-badge" alt="Release"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.7+-blue?style=for-the-badge&logo=python" alt="Python"></a>
  <a href="https://github.com/project-hellhound-org/DNwatch/blob/main/LICENSE"><img src="https://img.shields.io/github/license/project-hellhound-org/DNwatch?style=for-the-badge" alt="License"></a>
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Windows-blue?style=for-the-badge" alt="OS">
</p>

<p align="center">
  <b>DNwatch</b> is an enterprise-grade, autonomous LDAP injection security toolkit designed for high-fidelity vulnerability discovery and exploitation. It implements advanced detection oracles, polymorphic bypass chains, and stateful memory tracking to uncover deep-seated LDAP flaws.
</p>

---

## ⚡ Tactical Enhancements

| Feature | Description |
| :--- | :--- |
| **Autonomous Discovery** | Intelligent crawler with form-based endpoint extraction and recursive parameter discovery. |
| **Polymorphic WAF Bypass** | Real-time payload mutation engine designed to evade modern web application firewalls. |
| **Three-Step Verification** | Multi-stage deterministic proof chain to eliminate false positives and verify exploitability. |
| **Blind Data Harvesting** | High-speed boolean-based data extraction engine for LDAP directory enumeration. |
| **Control Plane Intel** | Integrated memory system that tracks payload efficacy and adapts to target defenses. |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/project-hellhound-org/DNwatch.git
cd DNwatch

# Run the professional installer
chmod +x install.sh
./install.sh
```

### Basic Usage

```bash
# Scan a target with default settings
dnwatch http://nexus-corp.internal

# Scan with custom request budget and threads
dnwatch http://nexus-corp.internal --threads 12 --budget 1500
```

## 🛠️ Engine Deep-Dive

DNwatch operates through a tiered detection pipeline, ensuring maximum coverage while maintaining a low noise profile:

1.  **Phase 1: Surface Recon**: Identifies endpoints, probes for liveness, and fingerprints the WAF.
2.  **Phase 2: Baseline Calibration**: Establishes behavioral baselines for authentic vs. non-authentic responses.
3.  **Phase 3: Tiered Injection**: Executes adaptive payloads ranging from simple metacharacters to complex boolean filters.
4.  **Phase 4: Deterministic Proof**: Verifies hits using a three-way differential analysis (TRUE, FALSE, and Error states).
5.  **Phase 5: Reporting**: Generates actionable handoff documents and executive HTML reports.

## 📊 Command Line Interface

| Flag | Description |
| :--- | :--- |
| `--auth-url` | Specify a dedicated URL for authentication testing. |
| `--threads` | Number of concurrent worker threads (default: 8). |
| `--budget` | Global request limit to prevent accidental DoS (default: 800). |
| `--force-scan` | Bypass Tier-0 qualification and scan all identified parameters. |
| `--verbose` | Enable detailed tactical logging for execution tracking. |

## 📜 Disclaimer

This tool is intended for professional security researchers and authorized penetration testers only. Unauthorized use against targets without explicit permission is strictly prohibited.

<p align="center">
  Developed with ❤️ by <a href="https://github.com/project-hellhound-org">Project Hellhound</a>
</p>
