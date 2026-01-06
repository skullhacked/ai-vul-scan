# AI Vulnerability Scanner

A production-grade, offline-capable AI Vulnerability Scanner designed for authorized defensive security testing. Features a cyberpunk-styled SOC dashboard with real-time scanning, AI-powered analysis, and comprehensive reporting.

## 🎯 Features

- **Offline AI Analysis**: Uses local AI models (Ollama) for vulnerability analysis
- **Real-time Scanning**: WebSocket-based live progress updates
- **Comprehensive Scanning**:
  - TCP port scanning
  - HTTP security headers analysis
  - TLS/SSL configuration review
  - OWASP Top 10 pattern detection
  - Server information gathering
- **Cyberpunk UI**: High-fidelity SOC dashboard with animations and glassmorphism
- **Security-First**: Authorization requirements and target restrictions
- **Report Generation**: HTML reports with cyber styling

## 🛠️ Tech Stack

### Backend
- Python 3.11+
- FastAPI (async)
- SQLite database
- WebSocket support
- Modular scanner engine

### Frontend
- Vanilla JavaScript
- CSS animations and transitions
- Canvas/SVG visualizations
- Real-time WebSocket updates

### AI Integration
- Ollama (local inference)
- Supports llama2, mistral, codellama, and other models

## 📦 Installation

### Prerequisites

1. **Python 3.11+** installed
2. **Ollama** installed and running (optional, for AI analysis)
   ```bash
   # Install Ollama from https://ollama.ai
   # Then pull a model:
   ollama pull llama2
   ```

### Setup

1. **Clone or navigate to the project directory**

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure settings** (optional)
   Create a `.env` file:
   ```env
   HOST=127.0.0.1
   PORT=8000
   AI_ENABLED=true
   OLLAMA_BASE_URL=http://localhost:11434
   OLLAMA_MODEL=llama2
   ```

## 🚀 Usage

### Start the Server

```bash
# From project root
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Or use the included script:
```bash
python backend/main.py
```

### Access the Dashboard

Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### Running a Scan

1. **Enter Target**: Enter an IP address, domain, or URL (e.g., `127.0.0.1`, `localhost`, `example.com`)
2. **Authorize**: Check the authorization checkbox
3. **Start Scan**: Click the "START SCAN" button
4. **Monitor Progress**: Watch real-time progress updates and animated visualizations
5. **Review Results**: View vulnerabilities with AI analysis and recommendations

### Download Reports

After a scan completes, you can download an HTML report:
```
http://127.0.0.1:8000/api/scan/{scan_id}/report
```

## 🔐 Security & Ethics

### Authorization Required
- All scans require explicit authorization via checkbox
- This tool is designed ONLY for defensive security testing

### Target Restrictions
- By default, scans are restricted to:
  - localhost
  - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - User-verified domains

### Passive Analysis Only
- No exploitation
- No brute force attacks
- No authentication bypass attempts
- Safe, read-only analysis

## 🧠 AI Configuration

### Using Ollama

1. **Install Ollama**: https://ollama.ai
2. **Pull a model**:
   ```bash
   ollama pull llama2
   # or
   ollama pull mistral
   # or
   ollama pull codellama
   ```
3. **Start Ollama** (usually runs automatically)
4. **Configure in `.env`**:
   ```env
   AI_ENABLED=true
   OLLAMA_BASE_URL=http://localhost:11434
   OLLAMA_MODEL=llama2
   ```

### Disabling AI

Set in `.env`:
```env
AI_ENABLED=false
```

The scanner will work without AI, but won't provide AI-powered analysis and recommendations.

## 📊 Scanner Capabilities

### Port Scanning
- TCP connect scanning
- Common ports (21, 22, 23, 25, 53, 80, 443, etc.)
- Service detection

### HTTP Security Headers
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Content-Security-Policy
- Referrer-Policy
- And more...

### TLS/SSL Analysis
- Protocol version detection
- Cipher suite analysis
- Certificate validation
- Expiration checking

### OWASP Top 10 Detection
- Broken Access Control
- Cryptographic Failures
- Injection vulnerabilities (passive detection)
- Security Misconfigurations
- Authentication failures

## 🎨 UI Features

- **Dark Cyberpunk Theme**: Neon accents (cyan, purple, green)
- **Glassmorphism**: Frosted glass effects
- **Animated Grid Background**: Subtle moving grid
- **Scan Line Animation**: Terminal-style scan effect
- **Radar Visualization**: Real-time scanning animation
- **Progress Ring**: Animated circular progress indicator
- **Severity Badges**: Glowing severity indicators
- **Smooth Transitions**: Micro-interactions throughout

## 📁 Project Structure

```
myproject/
├── backend/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── database.py          # Database models
│   ├── routes.py            # API routes
│   ├── websocket_manager.py # WebSocket handling
│   ├── reports.py           # Report generation
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py        # Main scanner engine
│   │   ├── port_scanner.py  # Port scanning
│   │   ├── http_analyzer.py # HTTP analysis
│   │   ├── tls_analyzer.py  # TLS/SSL analysis
│   │   └── owasp_detector.py # OWASP detection
│   └── ai/
│       ├── __init__.py
│       └── analyzer.py      # AI analysis
├── frontend/
│   ├── index.html           # Main HTML
│   ├── styles.css           # Cyberpunk styling
│   └── app.js               # Frontend logic
├── reports/                 # Generated reports
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🐛 Troubleshooting

### Ollama Connection Error
- Ensure Ollama is running: `ollama list`
- Check `OLLAMA_BASE_URL` in `.env`
- Verify model is pulled: `ollama list`

### Port Already in Use
- Change `PORT` in `.env` or use `--port` flag
- Example: `uvicorn backend.main:app --port 8001`

### Database Errors
- Delete `scanner.db` to reset database
- Check file permissions

### WebSocket Connection Failed
- Ensure server is running
- Check browser console for errors
- Verify firewall settings

## 📝 Logging

Logs are written to:
- Console output
- `scanner.log` file

## 🔧 Development

### Running in Development Mode

```bash
python -m uvicorn backend.main:app --reload
```

### Adding New Scanner Modules

1. Create module in `backend/scanner/`
2. Implement scan logic
3. Integrate in `backend/scanner/engine.py`
4. Add to scan pipeline

### Customizing UI

- Edit `frontend/styles.css` for styling
- Modify `frontend/app.js` for behavior
- Update `frontend/index.html` for structure

## ⚠️ Disclaimer

This tool is designed for **authorized defensive security testing only**. Users are responsible for ensuring they have proper authorization before scanning any target. The developers are not responsible for misuse of this tool.

## 📄 License

This project is provided as-is for educational and authorized security testing purposes.

## 🤝 Contributing

This is a production-grade tool. Contributions should maintain:
- Security-first approach
- Code quality and documentation
- UI/UX excellence
- Offline capability

---

**Built for Security Operations Centers (SOC) and Defensive Security Teams**

