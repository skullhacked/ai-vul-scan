# Quick Start Guide

Get the AI Vulnerability Scanner running in 5 minutes!

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 2: (Optional) Setup AI

If you want AI-powered analysis:

1. Install Ollama from https://ollama.ai
2. Pull a model:
   ```bash
   ollama pull llama2
   ```
3. Ensure Ollama is running (usually automatic)

The scanner works without AI, but won't provide AI analysis.

## Step 3: Start the Server

```bash
python run.py
```

Or:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

## Step 4: Open the Dashboard

Open your browser:
```
http://127.0.0.1:8000
```

## Step 5: Run Your First Scan

1. Enter a target (e.g., `127.0.0.1` or `localhost`)
2. Check the authorization checkbox
3. Click "START SCAN"
4. Watch the real-time progress!

## Example Targets

- `127.0.0.1` - Localhost
- `localhost` - Localhost
- `192.168.1.1` - Local network device
- `example.com` - External domain (requires authorization)

## Troubleshooting

**Port already in use?**
- Change port: `python run.py` and edit `backend/config.py` or use `--port 8001`

**Ollama not working?**
- Check: `ollama list`
- Start: `ollama serve`
- Or disable AI in `.env`: `AI_ENABLED=false`

**Database errors?**
- Delete `scanner.db` and restart

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Customize settings in `.env`
- Explore the scanner modules in `backend/scanner/`

---

**Ready to scan!** 🚀

