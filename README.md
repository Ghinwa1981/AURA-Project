# AURA // Strategic Neural Auditor

AURA (Strategic Neural Auditor) is a production-grade, modular Python FastAPI prototype designed to act as an interactive security, alignment, and data compliance dashboard. 

The application implements a cognitive auditing layer that screens incoming text payloads (e.g., user inputs, API logs, model prompts, and system documents) for structural anomalies, security violations, adversarial prompt manipulations, and misinformation profiles.

---

## 🌌 System Architecture

AURA is structured for high modularity, ensuring that scanning logic, backend routing, and user interface delivery are cleanly decoupled.

```
workspace/
├── main.py                     # FastAPI server, routing, and endpoint handlers
├── requirements.txt            # System dependencies
├── README.md                   # System blueprint & Context Engineering docs
├── services/
│   └── auditor.py              # AURA auditor core & pattern scanning service
└── templates/
    └── index.html              # Custom glassmorphic HTML5/CSS3 dashboard UI
```

---

## 🧠 Context Engineering & Heuristic Engine

AURA operates on a multi-pass pipeline where payloads are streamed through four distinct scanners. Each scanner is rule-engineered to trigger on target language vectors:

### 1. Security Scanner (`SecurityScanner`)
Looks for indicators of active system compromises or code injections.
* **SQL Injection (SQLi)**: Identifies tautological queries (e.g., `' OR 1=1`), DDL/DML mutations (`DROP TABLE`, `UPDATE SET`), and metadata harvesting requests (`UNION SELECT`).
* **Cross-Site Scripting (XSS)**: Screens for script tags, execution event listeners (`onerror`, `onload`), and inline `javascript:` schema URIs.
* **Path Traversal**: Flags relative parent directories (`../../`) and direct system files (`etc/passwd`, `win.ini`).
* **System Command Injection**: Catches destructive console calls (`rm -rf`, `format c:`, shell command execution pipelines).

### 2. Adversarial Scanner (`AdversarialScanner`)
Flags prompt hijackings, developer persona overrides, and jailbreak commands.
* **Instruction Overrides**: Matches directives seeking to ignore preceding guidelines (e.g., `"ignore all previous instructions"`).
* **Role Hijacking**: Detects forced personas, system override clearances, or DAN/developer-mode commands.
* **Spoofing**: Identifies mock Markdown/separator systems mimicking backend roles (e.g., `<system>`, `=== SYSTEM ===`).

### 3. Anomaly Scanner (`AnomalyScanner`)
Triggers on sensitive data leaks and high-entropy code formations.
* **Credentials**: Matches Google API keys, OpenAI tokens, Slack API keys, and database connection strings.
* **Cryptographic Files**: Matches structural block delimiters for private keys (`-----BEGIN PRIVATE KEY-----`).
* **Personal Identifiable Information (PII)**: Flags structural matches for 16-digit credit cards, exposed email addresses, and UUIDs.

### 4. Misinformation Scanner (`MisinformationScanner`)
Evaluates rhetorical frameworks for credibility risks.
* **Sensationalism**: Detects clickbait patterns ("they don't want you to know", "scientists are silent").
* **Hyperbolic Absolutes**: Identifies unsubstantiated extreme assertions ("absolute proof", "undeniable facts reveal").
* **Virality Hooks**: Flags chain-distribution hooks ("forward this to everyone", "share before it's deleted").

### ⚖️ Risk Aggregation & Scoring Strategy

Rather than simple boolean flags, AURA computes a weighted score to evaluate compound threats:
* **Category Weights**:
  * Security Exploits: **35%** of aggregate score
  * Adversarial Alignment: **30%** of aggregate score
  * Data Anomalies / Leaks: **20%** of aggregate score
  * Information Credibility: **15%** of aggregate score
* **Compounding Threat Multiplier**: If threats are flagged in multiple domains, a multiplier boosts the score:
  $$\text{Multiplier} = 1.0 + \big(0.10 \times (\text{Categories Flagged} - 1)\big)$$
* **Severity Classification**:
  * **0 - 19**: `Low`
  * **20 - 49**: `Medium`
  * **50 - 79**: `High`
  * **80 - 100**: `Critical`

---

## ⚙️ Installation & Setup

Follow these steps to deploy and run AURA locally.

### Prerequisites
* Python 3.10 or higher.
* `pip` package manager.

### 1. Clone & Navigate
Ensure you are in the workspace folder:
```bash
cd C:\Users\l\.gemini\antigravity\scratch\workspace
```

### 2. Create and Activate Virtual Environment
Setting up a virtual environment isolates dependencies:
```bash
# Create environment
python -m venv .venv

# Activate on Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Activate on Windows (Command Prompt)
.venv\Scripts\activate.bat

# Activate on macOS/Linux
source .venv/bin/activate
```

### 3. Install Dependencies
Run pip to install the required framework assets:
```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Server

Start the FastAPI ASGI server using Uvicorn:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

* `--reload`: Automatically restarts the server whenever file modifications are saved (ideal for developer iteration).
* `--host 127.0.0.1`: Binds to local loopback interface.
* `--port 8000`: Binds the web service port.

Once started, open your browser and navigate to:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 📡 API Endpoints

### `GET /`
Renders and serves the interactive security cockpit client interface.

### `POST /api/audit`
Processes a textual payload for full diagnostic evaluation.
* **Request Body**:
  ```json
  {
    "payload": "SELECT * FROM users WHERE username = 'admin' OR '1'='1';"
  }
  ```
* **Response Body**: Returns the fully aggregated `AuditReport` schema containing categorised flag analysis, findings, scores, and severity classifications.

### `GET /api/history`
Retrieves a JSON array of all past audits processed during the current session.

### `POST /api/history/clear`
Wipes the active session history array clean.

---

## 🔮 Future Enhancements
1. **Dynamic Sandbox Evaluation**: Add secure, containerized compilation to analyze code fragments.
2. **Deep-Learning Classifiers**: Connect LLM-driven classifiers (such as small local transformers) to augment regex match checks.
3. **Database Persistence**: Migrate from the in-memory array to a SQLite/PostgreSQL layer for durable telemetry tracking.
