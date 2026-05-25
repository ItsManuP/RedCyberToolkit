```markdown
# 🔴 RedCyber ToolKIT – Multi-Agent Pentest Framework

**RedCyber ToolKIT** è un framework modulare di penetration testing basato su agenti specializzati (Recon, CVE, Auth, Exploit, Traffic, Report) orchestrati da un core centralizzato.  
Progettato per ambienti autorizzati, supporta sia esecuzione nativa su Linux che containerizzata con Docker (funzionante anche su Windows).


## 🚀 Funzionalità principali

| Fase | Agente | Descrizione |
|------|--------|-------------|
| 1. Discovery | `recon` | Port scanning (nmap o socket), OS fingerprinting, banner grabbing |
| 2. CVE Check | `cve` | Ricerca vulnerabilità su NVD API + database offline, scoring CVSS |
| 3. Auth Attack | `auth` | Test credenziali di default e brute-force su SSH, FTP, HTTP, MySQL, PostgreSQL, Redis |
| 4. Exploit | `exploit` | Path traversal, LFI, command injection, RCE (es. Apache, Redis) |
| 5. Traffic | `traffic` | Analisi header HTTP, endpoint probing, SSL check, rilevamento info leakage |
| 6. Report | `report` | Generazione report in JSON, Markdown e TXT con remediation |

---

## 📦 Requisiti

- **Docker** (opzione consigliata) oppure **Python 3.8+** con `pip`
- **nmap** (opzionale, ma raccomandato per discovery completa)
- Sistema operativo: Linux (nativo) o Windows/macOS con Docker

---

## 🐳 Installazione ed esecuzione con Docker (consigliata)

### 1. Clona il repository

```bash
git clone https://github.com/tuo-username/redteam-toolkit.git
cd redteam-toolkit
```

### 2. Costruisci l’immagine Docker

```bash
docker build -t redteam-toolkit .
```

### 3. Esegui un test autorizzato

```bash
docker run --rm --privileged redteam-toolkit --target 192.168.1.100 --yes
```

> **`--privileged`** è necessario solo per il raw packet sniffing (fase TRAFFIC). Se non ti serve, puoi ometterlo.

### 4. Montare la cartella dei report (opzionale)

```bash
docker run --rm --privileged -v ${PWD}/reports:/app/reports redteam-toolkit --target 192.168.1.100 --yes
```

I report verranno salvati nella cartella `reports/` del tuo host.

---

## 🖥️ Esecuzione nativa su Linux

### 1. Installa le dipendenze di sistema

```bash
sudo apt update
sudo apt install nmap python3 python3-pip
```

### 2. Installa i pacchetti Python

```bash
pip3 install -r requirements.txt
```

### 3. Esegui

```bash
python3 main.py --target 192.168.1.100 --yes
```

---

## 🎮 Opzioni della linea di comando

| Argomento | Descrizione | Default |
|-----------|-------------|---------|
| `--target` | IP o hostname del target | **obbligatorio** |
| `--phases` | Fasi da eseguire (`all` o lista separata da virgole: `discovery,cve,auth`) | `all` |
| `--port-range` | Range di porte per lo scan | `1-1024` |
| `--no-nmap` | Usa socket scan invece di nmap | `False` |
| `--safe-mode` | Limita exploit a operazioni read‑only | `True` |
| `--use-nvd-api` | Interroga NVD API (richiede internet) | `False` |
| `--max-attempts` | Numero massimo di tentativi brute‑force | `100` |
| `--yes` | Salta il promemoria di autorizzazione | `False` |

### Esempi

```bash
# Solo discovery + report
python main.py --target 10.0.0.5 --phases discovery,report --yes

# Con nmap disabilitato e range porte esteso
python main.py --target example.com --no-nmap --port-range 1-10000 --yes

# Con API NVD e modalità safe disabilitata (ATTENZIONE!)
python main.py --target 192.168.1.100 --use-nvd-api --safe-mode False --yes
```

---

## 📁 Struttura del progetto

```
redteam_toolkit/
├── main.py                 # Entry point CLI
├── core/
│   ├── base_agent.py       # Classe astratta per tutti gli agent
│   └── orchestrator.py     # Orchestrator, SessionState, MessageBus
├── agents/
│   ├── recon_agent.py
│   ├── cve_agent.py
│   ├── auth_agent.py
│   ├── exploit_agent.py
│   ├── traffic_agent.py
│   └── report_agent.py
├── utils/
│   └── consent.py          # Richiesta autorizzazione
├── reports/                # Output dei report (creata automaticamente)
├── requirements.txt
└── Dockerfile
```

---

## 📄 Output dei report

Al termine della pipeline, il Report Agent genera tre file nella cartella `reports/`:

- `report_<session-id>_<timestamp>.json` – dati strutturati
- `report_<session-id>_<timestamp>.md` – formato Markdown leggibile
- `report_<session-id>_<timestamp>.txt` – formato testo semplice

Ogni report include:
- Riepilogo del rischio complessivo (CRITICAL/HIGH/MEDIUM/LOW/NONE)
- Elenco CVE trovate con CVSS
- Credenziali scoperte
- Exploit riusciti
- Raccomandazioni di remediation

---

## ⚠️ Avvertenze legali

> **Questo strumento può essere utilizzato SOLO su sistemi per i quali si dispone di esplicita autorizzazione scritta.**  
> L’uso improprio è vietato e può costituire reato. L’autore non è responsabile di eventuali abusi.

---

## ⚠️ Limitazioni note su Windows senza Docker

- Lo scanning raw socket (`--privileged`) non è supportato.
- Alcuni exploit (es. path traversal con `/etc/passwd`) hanno senso solo contro target Linux.
- `nmap` deve essere installato manualmente e aggiunto al PATH.

**Soluzione**: usa Docker (come descritto sopra) per ottenere un ambiente Linux completo e funzionante anche su Windows.

---

## 📜 Licenza

Questo progetto è distribuito per scopi educativi e di testing autorizzato.  
Non è consentito l’uso per attività illecite.

---

## 🤝 Contributi

Pull request e suggerimenti sono benvenuti. Apri una issue per discutere nuove funzionalità o bug.

```
