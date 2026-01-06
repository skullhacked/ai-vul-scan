# Deployment Guide

## Quick Deploy Options

### Railway (Recommended)
1. Go to [railway.app](https://railway.app)
2. Click "New Project" → "Deploy from GitHub repo"
3. Connect your repository
4. Railway will auto-detect and deploy
5. Your app will be live at `https://your-app.railway.app`

### Render
1. Go to [render.com](https://render.com)
2. Create new "Web Service"
3. Connect GitHub repository
4. Build Command: `pip install -r requirements.txt`
5. Start Command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
6. Deploy!

### Heroku
1. Install Heroku CLI
2. `heroku create your-app-name`
3. `git push heroku main`
4. Done!

### Vercel (Serverless)
1. Install Vercel CLI: `npm i -g vercel`
2. Run `vercel` in project directory
3. Follow prompts
4. Deploy!

## Environment Variables

Set these in your hosting platform:

```env
HOST=0.0.0.0
PORT=8000
AI_ENABLED=false  # Set to true if you have Ollama
OLLAMA_BASE_URL=http://localhost:11434
DATABASE_URL=sqlite+aiosqlite:///./scanner.db
```

## Production Checklist

- [ ] Set `DEBUG=false` in production
- [ ] Use environment variables for secrets
- [ ] Enable HTTPS
- [ ] Set up proper database (PostgreSQL for production)
- [ ] Configure CORS properly
- [ ] Set up monitoring/logging
- [ ] Configure rate limiting

## Database Migration (Production)

For production, use PostgreSQL instead of SQLite:

1. Update `DATABASE_URL` in `.env`:
   ```
   DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname
   ```

2. Install: `pip install asyncpg`

3. Update `requirements.txt` to include `asyncpg`

## Notes

- The scanner is optimized for fast scanning (60 second timeout)
- Port scanning is skipped for web URLs
- All operations have timeouts to prevent hanging
- Ready for production deployment!

