# 🔴 RedCyber ToolKIT – Multi-Agent Pentest Framework

**RedCyber ToolKIT** is a modular penetration testing framework based on specialized agents (Recon, CVE, Auth, Exploit, Traffic, Report) orchestrated by a centralized core.  
Designed for authorized environments, it supports both native execution on Linux and containerized execution with Docker (also working on Windows).

## 🚀 Key Features

| Phase | Agent | Description |
|------|--------|-------------|
| 1. Discovery | `recon` | Port scanning (nmap or socket), OS fingerprinting, banner grabbing |
| 2. CVE Check | `cve` | Vulnerability lookup through the NVD API + offline database, CVSS scoring |
| 3. Auth Attack | `auth` | Default credential testing and brute-force on SSH, FTP, HTTP, MySQL, PostgreSQL, Redis |
| 4. Exploit | `exploit` | Path traversal, LFI, command injection, RCE (e.g. Apache, Redis) |
| 5. Traffic | `traffic` | HTTP header analysis, endpoint probing, SSL checks, information leakage detection |
| 6. Report | `report` | Report generation in JSON, Markdown, and TXT with remediation guidance |

---

## 📦 Requirements

- **Docker** (recommended option) or **Python 3.8+** with `pip`
- **nmap** (optional, but recommended for full discovery)
- Operating system: Linux (native) or Windows/macOS with Docker

---

## 🐳 Installation and Execution with Docker (Recommended)

### 1. Clone the repository

```bash
git clone [https://github.com/your-username/redteam-toolkit.git](https://github.com/your-username/redteam-toolkit.git)
cd redteam-toolkit
```

### 2. Build the Docker image

```bash
docker build -t redteam-toolkit .
```

### 3. Run an authorized test

```bash
docker run --rm --privileged redteam-toolkit --target 192.168.1.100 --yes
```

> **`--privileged`** is only required for raw packet sniffing (TRAFFIC phase). If you do not need it, you can omit it.

### 4. Mount the reports folder (optional)
### Without this option, the folder is not created and we do not have any report information apart from what is shown in the shell
```bash
docker run --rm --privileged -v ${PWD}/reports:/app/reports redteam-toolkit --target 192.168.1.100 --yes
```

Reports will be saved in the `reports/` folder on your host.

---

## 🖥️ Native Execution on Linux

### 1. Install system dependencies

```bash
sudo apt update
sudo apt install nmap python3 python3-pip
```

### 2. Install Python packages

```bash
pip3 install -r requirements.txt
```

### 3. Run

```bash
python3 main.py --target 192.168.1.100 --yes
```

---

## 🎮 Command-Line Options

| Argument | Description | Default |
|-----------|-------------|---------|
| `--target` | Target IP or hostname | **required** |
| `--phases` | Phases to run (`all` or a comma-separated list: `discovery,cve,auth`) | `all` |
| `--port-range` | Port range for scanning | `1-1024` |
| `--no-nmap` | Use socket scan instead of nmap | `False` |
| `--safe-mode` | Restrict exploits to read-only operations | `True` |
| `--use-nvd-api` | Query the NVD API (requires internet access) | `False` |
| `--max-attempts` | Maximum number of brute-force attempts | `100` |
| `--yes` | Skip the authorization reminder | `False` |

### Examples

```bash
# Discovery + report only
python main.py --target 10.0.0.5 --phases discovery,report --yes

# With nmap disabled and extended port range
python main.py --target example.com --no-nmap --port-range 1-10000 --yes

# With NVD API and safe mode disabled (WARNING!)
python main.py --target 192.168.1.100 --use-nvd-api --safe-mode False --yes
```


## 📄 Report Output

At the end of the pipeline, the Report Agent generates three files in the `reports/` folder:

- `report_<session-id>_<timestamp>.json` – structured data
- `report_<session-id>_<timestamp>.md` – readable Markdown format
- `report_<session-id>_<timestamp>.txt` – plain text format

Each report includes:
- Overall risk summary (CRITICAL/HIGH/MEDIUM/LOW/NONE)
- List of discovered CVEs with CVSS scores
- Discovered credentials
- Successful exploits
- Remediation recommendations

---

## ⚠️ Legal Warnings

> **This tool may be used ONLY on systems for which explicit written authorization has been obtained.**  
> Improper use is prohibited and may constitute a criminal offense. The author is not responsible for any abuse.

---

## ⚠️ Known Limitations on Windows Without Docker

- Raw socket scanning (`--privileged`) is not supported.
- Some exploits (e.g. path traversal with `/etc/passwd`) only make sense against Linux targets.
- `nmap` must be installed manually and added to the PATH.

**Solution**: use Docker (as described above) to get a complete Linux environment that also works on Windows.

---

## 📜 License

This project is distributed for educational purposes and authorized testing.  
Use for illegal activities is not permitted.

---

## 🤝 Contributions

Pull requests and suggestions are welcome. Open an issue to discuss new features or bugs.
