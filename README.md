# Website Security Score Checker

A beginner-friendly full-stack web app that fetches a website's HTTP response
headers and scores them against a small set of security rules, returning a
score out of 100 with a list of issues and actionable suggestions.

---

## Folder Structure

```
security-checker/
├── server.js          ← Express backend (scoring logic, header checks)
├── package.json       ← Dependencies and npm scripts
├── public/
│   ├── index.html     ← Single-page UI
│   ├── style.css      ← Dark-themed styling + SVG gauge animation
│   └── script.js      ← Frontend fetch, DOM rendering, error handling
└── README.md          ← This file
```

---

## How Scoring Works

The score is calculated out of **100 points**:

| Check | Points | Notes |
|---|---|---|
| Valid URL format | +10 | URL parses correctly as http/https |
| HTTPS scheme | +30 | URL starts with `https://` |
| `Content-Security-Policy` header | +14 | Prevents XSS attacks |
| `X-Frame-Options` header | +13 | Prevents clickjacking |
| `Strict-Transport-Security` header | +13 | Forces HTTPS connections |
| **Bonus**: HTTPS + all 3 headers | +20 | Only awarded when all are present |
| **Maximum total** | **100** | |

### Risk Levels

| Score | Risk Level | Badge Color |
|---|---|---|
| 80 – 100 | ✅ Low Risk | Green |
| 50 – 79 | ⚠️ Medium Risk | Amber |
| 0 – 49 | 🔴 High Risk | Red |

---

## Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) v18 or later

### Install Dependencies

```bash
cd security-checker
npm install
```

### Run the App

```bash
npm start
```

You should see:

```
Server running at http://localhost:5000
```

### Open in Your Browser

Navigate to: **http://localhost:5000**

Enter any URL (e.g., `https://github.com`) and click **Check Security**.

---

## Testing with curl

You can test the API directly without the browser using **curl**:

### Valid HTTPS URL

```bash
curl -X POST http://localhost:5000/check-security \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://github.com\"}"
```

### Missing URL (validation error)

```bash
curl -X POST http://localhost:5000/check-security \
  -H "Content-Type: application/json" \
  -d "{}"
```

### Invalid URL format

```bash
curl -X POST http://localhost:5000/check-security \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"not a url\"}"
```

### Expected Response Shape

Every response (success or error) uses the same JSON structure:

```json
{
  "score": 83,
  "status": "Low Risk",
  "issues": ["No major security issues detected. Great job!"],
  "suggestions": ["Your site follows all the security best practices we check. Keep it up!"]
}
```

---

## Security Headers Checked

| Header | Purpose |
|---|---|
| `Content-Security-Policy` | Restricts which resources the browser can load; mitigates XSS. |
| `X-Frame-Options` | Prevents the page being embedded in an `<iframe>`; stops clickjacking. |
| `Strict-Transport-Security` | Forces browsers to always use HTTPS for this domain. |

---

## Extending the App

Want to check more headers? Great candidates:

- `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing
- `Referrer-Policy` — controls what referrer info is sent
- `Permissions-Policy` — restricts browser features (camera, mic, etc.)
- Cookie flags (`HttpOnly`, `Secure`, `SameSite`)

Add each check in the scoring block inside `server.js` and adjust the point
values so they still sum to 100 (or raise the max accordingly).
