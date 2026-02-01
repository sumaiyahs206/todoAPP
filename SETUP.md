# 🚀 CuToDo Backend Setup Guide

Complete guide to setting up the CuToDo authentication and API backend.

---

## 📋 Prerequisites

Before you begin, ensure you have installed:

- **Node.js** (v16 or higher) - [Download](https://nodejs.org/)
- **PostgreSQL** (v12 or higher) - [Download](https://www.postgresql.org/download/)
- **npm** or **yarn** package manager
- **Git** for version control

---

## 🛠️ Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/cutodo.git
cd cutodo/backend
```

### 2. Install Dependencies

```bash
npm install
```

This will install all required packages:
- express (web framework)
- bcrypt (password hashing)
- jsonwebtoken (JWT tokens)
- pg (PostgreSQL client)
- nodemailer (email sending)
- And more...

### 3. Setup PostgreSQL Database

#### Option A: Local PostgreSQL

```bash
# Login to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE cutodo;

# Create user (optional but recommended)
CREATE USER cutodo_app WITH PASSWORD 'your_secure_password';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cutodo TO cutodo_app;

# Exit psql
\q
```

#### Option B: Using Cloud PostgreSQL

Popular options:
- **Heroku Postgres** (free tier available)
- **Railway** (free tier available)
- **Neon** (serverless PostgreSQL)
- **Supabase** (includes auth features)

Get your connection string from the provider.

### 4. Run Database Schema

```bash
# Apply the schema
psql -U postgres -d cutodo -f database/schema.sql

# Or if using your app user:
psql -U cutodo_app -d cutodo -f database/schema.sql
```

You should see:
```
✅ Database schema setup complete!
Tables created: users, tasks, sessions
```

### 5. Configure Environment Variables

```bash
# Copy the example file
cp .env.example .env

# Edit the .env file with your actual values
nano .env  # or use your preferred editor
```

**Required Configuration:**

```env
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/cutodo

# JWT Secret (generate a secure random string)
JWT_SECRET=your-super-secret-jwt-key-min-32-characters

# Email (using Gmail as example)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# App URLs
APP_URL=http://localhost:3000
CLIENT_URL=http://localhost:3000
```

#### Generate JWT Secret

```bash
# Run this command to generate a secure secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 6. Setup Email (Gmail Example)

For Gmail, you need an **App Password**:

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable 2-Step Verification
3. Go to [App Passwords](https://myaccount.google.com/apppasswords)
4. Generate a new app password
5. Use this password in your `.env` file

**Alternative Email Providers:**
- SendGrid (recommended for production)
- Mailgun
- Amazon SES
- Postmark

### 7. Start the Server

#### Development Mode (with auto-reload)
```bash
npm run dev
```

#### Production Mode
```bash
npm start
```

You should see:
```
🚀 Server running on port 3001
✅ Database connected successfully
✅ Email service ready
🔒 Environment: development
```

---

## 🧪 Testing the Setup

### 1. Health Check

```bash
curl http://localhost:3001/api/health
```

Expected response:
```json
{
  "status": "ok",
  "timestamp": "2026-02-01T12:00:00.000Z"
}
```

### 2. Test Registration

```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'
```

Expected response:
```json
{
  "success": true,
  "message": "Account created! Please check your email to verify your account. 💕"
}
```

Check your email for the verification link!

### 3. Verify Email

Click the link in the email, or visit:
```
http://localhost:3001/api/auth/verify/YOUR_TOKEN_HERE
```

### 4. Test Login

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'
```

---

## 🔐 Security Checklist

Before deploying to production:

- [ ] Change `JWT_SECRET` to a secure random value
- [ ] Use strong `DATABASE_URL` password
- [ ] Enable HTTPS (`COOKIE_SECURE=true`)
- [ ] Set `NODE_ENV=production`
- [ ] Never commit `.env` file to git
- [ ] Add `.env` to `.gitignore`
- [ ] Use environment variables in hosting platform
- [ ] Enable database SSL/TLS
- [ ] Setup database backups
- [ ] Configure rate limiting properly
- [ ] Review CORS settings
- [ ] Setup monitoring (Sentry, etc.)
- [ ] Enable database connection pooling

---

## 📦 Deployment

### Deploy to Railway

1. Create account on [Railway.app](https://railway.app)
2. Create new project
3. Add PostgreSQL database
4. Deploy from GitHub
5. Set environment variables in Railway dashboard
6. Deploy!

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Link project
railway link

# Deploy
railway up
```

### Deploy to Heroku

```bash
# Install Heroku CLI
npm install -g heroku

# Login
heroku login

# Create app
heroku create cutodo-api

# Add PostgreSQL
heroku addons:create heroku-postgresql:mini

# Set environment variables
heroku config:set JWT_SECRET=your_secret_here
heroku config:set SMTP_HOST=smtp.gmail.com
# ... set all other env vars

# Deploy
git push heroku main

# Run migrations
heroku run node scripts/migrate.js
```

### Deploy to Vercel (Serverless)

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy
vercel

# Set environment variables in Vercel dashboard
```

### Deploy to VPS (DigitalOcean, Linode, etc.)

```bash
# SSH into server
ssh root@your-server-ip

# Install Node.js and PostgreSQL
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs postgresql

# Clone repository
git clone https://github.com/yourusername/cutodo.git
cd cutodo/backend

# Install dependencies
npm install --production

# Setup environment
cp .env.example .env
nano .env

# Use PM2 for process management
npm install -g pm2
pm2 start server.js --name cutodo-api
pm2 startup
pm2 save

# Setup Nginx reverse proxy
sudo apt-get install nginx
# Configure nginx to proxy port 3001
```

---

## 🔧 Troubleshooting

### Database Connection Issues

```bash
# Test PostgreSQL connection
psql $DATABASE_URL

# Check if PostgreSQL is running
sudo systemctl status postgresql

# View logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

### Email Not Sending

1. **Check SMTP credentials** - Make sure they're correct
2. **Enable "Less secure app access"** (Gmail) - Or use App Password
3. **Check firewall** - Port 587 or 465 must be open
4. **View server logs** - Check for error messages

```bash
# Test email with nodemailer test account
node -e "
const nodemailer = require('nodemailer');
nodemailer.createTestAccount().then(account => {
  console.log('Test account:', account.user, account.pass);
});
"
```

### JWT Errors

```bash
# Make sure JWT_SECRET is set
echo $JWT_SECRET

# Regenerate if needed
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Port Already in Use

```bash
# Find process using port 3001
lsof -i :3001

# Kill the process
kill -9 <PID>

# Or change the port in .env
echo "PORT=3002" >> .env
```

---

## 📊 Monitoring & Maintenance

### Setup Logging

```javascript
// Add to server.js
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});
```

### Database Maintenance

```bash
# Regular vacuum (run weekly)
psql $DATABASE_URL -c "VACUUM ANALYZE;"

# Clean up expired tokens (run daily via cron)
psql $DATABASE_URL -c "SELECT cleanup_expired_tokens();"

# Clean up expired sessions
psql $DATABASE_URL -c "SELECT cleanup_expired_sessions();"
```

### Backup Database

```bash
# Backup
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d).sql

# Restore
psql $DATABASE_URL < backup_20260201.sql
```

---

## 🐛 Common Errors & Solutions

| Error | Solution |
|-------|----------|
| `ECONNREFUSED` | PostgreSQL not running or wrong host/port |
| `invalid signature` | Wrong JWT_SECRET or token from different environment |
| `Email not verified` | User didn't click verification link |
| `Too many requests` | Rate limiter triggered - wait 15 minutes |
| `Account locked` | 5 failed login attempts - wait 15 minutes |

---

## 📚 API Documentation

Full API documentation available at:
- Swagger UI: `/api/docs` (when implemented)
- Postman Collection: `docs/postman_collection.json`

### Quick Reference

**Auth Endpoints:**
```
POST   /api/auth/register
POST   /api/auth/login
POST   /api/auth/logout
GET    /api/auth/verify/:token
POST   /api/auth/forgot-password
POST   /api/auth/reset-password/:token
GET    /api/auth/me
```

**Task Endpoints:** (require authentication)
```
GET    /api/tasks
POST   /api/tasks
GET    /api/tasks/:id
PUT    /api/tasks/:id
PATCH  /api/tasks/:id/toggle
DELETE /api/tasks/:id
GET    /api/tasks/stats/summary
```

---

## 🎯 Next Steps

1. **Implement frontend integration** - Connect React app to API
2. **Add tests** - Write unit and integration tests
3. **Setup CI/CD** - Automate testing and deployment
4. **Add monitoring** - Setup Sentry or similar
5. **Implement caching** - Add Redis for sessions
6. **Add 2FA** - Two-factor authentication
7. **API documentation** - Setup Swagger/OpenAPI

---

## 💡 Tips

1. **Use HTTPS in production** - Get free SSL from Let's Encrypt
2. **Setup database backups** - Automate daily backups
3. **Monitor error logs** - Setup alerts for errors
4. **Use environment-specific configs** - Different settings for dev/prod
5. **Keep dependencies updated** - Run `npm audit` regularly
6. **Rate limit API endpoints** - Prevent abuse
7. **Use prepared statements** - Already done with parameterized queries

---

## 📞 Support

- **Documentation**: Check this README
- **Issues**: Open a GitHub issue
- **Email**: support@cutodo.app

---

## ✅ Success Checklist

- [x] PostgreSQL database running
- [x] Database schema applied
- [x] Environment variables configured
- [x] Email service working
- [x] Server starts without errors
- [x] Registration works
- [x] Email verification works
- [x] Login works
- [x] JWT tokens working
- [x] Protected routes secured

---

**You're all set! Start building cute productivity! 💕**
