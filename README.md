# Log Analyzer 🔍

A cybersecurity tool that analyzes server logs to detect suspicious activity like brute force attacks, path scanners, and high volume IPs.

## Live Demo
- 🌐 Frontend: https://log-analyzer-five.vercel.app
- 🔧 Backend: https://log-analyzer-4wug.onrender.com

## Tech Stack
- **Frontend:** React, React Router, Axios
- **Backend:** Node.js, Express, Multer
- **Analysis:** Custom log parsing + pattern detection algorithms

## Features
- 📂 Upload Apache/Nginx log files (.log, .txt)
- 🔴 Detect **Brute Force** attacks (IPs with many 401/403 failures)
- 🟠 Detect **High Volume** IPs flooding the server
- 🟣 Detect **Scanners** doing path enumeration (many 404s)
- 📊 Dashboard with summary stats and top IP chart
- 🧹 Auto-cleanup of uploaded files after analysis

## Detection Algorithms
| Attack Type | Logic |
|---|---|
| Brute Force | IP with 10+ failed auth attempts (401/403) |
| High Volume | IP with 100+ total requests |
| Scanner | IP with 20+ 404 responses |

## Project Structure
```
log-analyzer/
├── client/               → React frontend
│   └── src/
│       ├── pages/
│       │   ├── Home.js      → file upload UI
│       │   └── Results.js   → analysis dashboard
│       └── components/
│           ├── Navbar.js
│           └── FileUpload.js → drag & drop upload
└── server/               → Node.js backend
    ├── index.js
    ├── routes/
    │   └── logs.js       → upload + analysis endpoint
    └── utils/
        ├── upload.js     → multer config
        └── parser.js     → detection algorithms
```

## Getting Started

### Backend
```bash
cd server
npm install
node index.js    # runs on port 5001
```

### Frontend
```bash
cd client
npm install
npm start        # runs on localhost:3000
```

### Test It
Use the included `sample.log` file to test — it contains simulated brute force and scanner activity.

## Status
✅ Fully deployed and live!
