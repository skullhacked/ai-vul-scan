# Free Hosting Guide for AI Vulnerability Scanner

## 🚀 Quick Deploy Options

### Option 1: Railway (Recommended - Easiest)
**Free Tier:** $5 credit/month, then pay-as-you-go

1. **Sign up** at [railway.app](https://railway.app)
2. **Create New Project** → "Deploy from GitHub repo"
3. **Connect your GitHub** repository
4. **Railway auto-detects** Python and deploys
5. **Add Environment Variables** (if needed):
   - `HOST=0.0.0.0`
   - `PORT=$PORT` (Railway sets this automatically)
   - `AI_ENABLED=true`
   - `AI_FALLBACK_ENABLED=true`
6. **Deploy!** Your app will be live at `https://your-app.railway.app`

**Pros:** Auto-detects, easy setup, good free tier
**Cons:** Requires credit card (but free tier is generous)

---

### Option 2: Render (100% Free)
**Free Tier:** 750 hours/month, sleeps after 15 min inactivity

1. **Sign up** at [render.com](https://render.com)
2. **New** → "Web Service"
3. **Connect GitHub** repository
4. **Configure:**
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
   - **Environment:** Python 3
5. **Add Environment Variables:**
   - `HOST=0.0.0.0`
   - `PORT=$PORT`
   - `AI_ENABLED=true`
   - `AI_FALLBACK_ENABLED=true`
6. **Deploy!** Your app will be at `https://your-app.onrender.com`

**Pros:** Completely free, no credit card needed
**Cons:** Sleeps after inactivity (first request takes ~30s to wake)

---

### Option 3: Fly.io (Free Tier)
**Free Tier:** 3 shared VMs, 160GB outbound data

1. **Install Fly CLI:** 
   ```bash
   # Windows (PowerShell)
   powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"
   ```
2. **Sign up** at [fly.io](https://fly.io)
3. **Login:**
   ```bash
   fly auth login
   ```
4. **Create app:**
   ```bash
   fly launch
   ```
5. **Deploy:**
   ```bash
   fly deploy
   ```

**Pros:** Good free tier, fast
**Cons:** Requires CLI setup

---

### Option 4: Vercel (Serverless - Free)
**Free Tier:** 100GB bandwidth/month

1. **Install Vercel CLI:**
   ```bash
   npm i -g vercel
   ```
2. **Login:**
   ```bash
   vercel login
   ```
3. **Deploy:**
   ```bash
   vercel
   ```
4. **Follow prompts** - Vercel will auto-detect Python

**Pros:** Fast, great for serverless
**Cons:** May need adjustments for WebSocket support

---

## 📋 Pre-Deployment Checklist

### 1. Update Database for Production
For production, use PostgreSQL instead of SQLite:

**Update `requirements.txt`:**
```txt
asyncpg>=0.29.0
```

**Update `.env` or environment variables:**
```env
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname
```

### 2. Environment Variables to Set

```env
# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false

# Database (use PostgreSQL for production)
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname

# AI (works without Ollama now!)
AI_ENABLED=true
AI_FALLBACK_ENABLED=true
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama2

# Security
ALLOWED_IP_RANGES=["*"]  # Or specific IPs
```

### 3. Update CORS (if needed)
In `backend/main.py`, update CORS origins:
```python
allow_origins=["*"]  # Or your specific domain
```

### 4. Create `.env` file (optional)
```env
HOST=0.0.0.0
PORT=8000
AI_ENABLED=true
AI_FALLBACK_ENABLED=true
```

---

## 🔧 Platform-Specific Setup

### Railway
- **No changes needed!** Railway auto-detects Python
- Uses `Procfile` if present
- Sets `$PORT` automatically

### Render
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- **Python Version:** 3.11

### Fly.io
Create `fly.toml`:
```toml
app = "your-app-name"
primary_region = "iad"

[build]

[env]
  PORT = "8000"

[[services]]
  internal_port = 8000
  protocol = "tcp"

  [[services.ports]]
    handlers = ["http"]
    port = 80

  [[services.ports]]
    handlers = ["tls", "http"]
    port = 443
```

### Vercel
Create `vercel.json` (already included):
```json
{
  "version": 2,
  "builds": [
    {
      "src": "backend/main.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "backend/main.py"
    }
  ]
}
```

---

## 🎯 Recommended: Railway (Easiest)

1. **Push code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/yourusername/your-repo.git
   git push -u origin main
   ```

2. **Go to Railway:**
   - New Project → Deploy from GitHub
   - Select your repo
   - Railway auto-deploys!

3. **Done!** Your app is live 🎉

---

## 🐛 Troubleshooting

### Database Issues
- **SQLite won't work on serverless** (Vercel, some Render plans)
- **Use PostgreSQL** for production
- Railway and Render offer free PostgreSQL databases

### WebSocket Issues
- **Vercel:** May need upgrade to Pro plan for WebSocket
- **Render/Railway:** WebSocket works fine

### Port Issues
- Always use `$PORT` environment variable
- Host should be `0.0.0.0` (not `127.0.0.1`)

### AI Analysis
- **Now works without Ollama!** Uses intelligent rule-based analysis
- If you want Ollama, install it on your server (Railway/Render support this)

---

## 📝 Quick Start Commands

### Railway
```bash
# Install Railway CLI (optional)
npm i -g @railway/cli

# Login
railway login

# Deploy
railway up
```

### Render
Just connect GitHub - no CLI needed!

### Fly.io
```bash
fly launch
fly deploy
```

---

## ✅ Post-Deployment

1. **Test your app:** Visit your deployed URL
2. **Check logs:** Most platforms have log viewers
3. **Update CORS:** If needed for your domain
4. **Set up custom domain:** (Optional) Most platforms support this

---

## 🎉 You're Live!

Your AI Vulnerability Scanner is now online and accessible from anywhere!

**Need help?** Check platform documentation or open an issue.

