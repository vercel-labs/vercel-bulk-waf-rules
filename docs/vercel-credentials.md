# Vercel Credentials Setup

This guide explains how to get the credentials needed to run the Vercel Bulk WAF Rules scripts.

## Prerequisites

### Dependencies

- `vercel` CLI v50.5.1+ (or uses `npx vercel@latest` automatically)
- `jq` - for JSON parsing
- `bc` - for calculations (usually pre-installed)

**Install on macOS:**

```bash
brew install jq
npm i -g vercel  # Optional, npx works too
```

**Install on Ubuntu/Debian:**

```bash
sudo apt-get install jq bc
npm i -g vercel  # Optional, npx works too
```

## Authentication Options

### Option 1: Vercel CLI Login (Recommended for Local Use)

The simplest approach for local development:

```bash
# Link your project (one-time setup)
cd /path/to/your/vercel/project
vercel link

# Authenticate
vercel login

# Run the script - PROJECT_ID and TEAM_ID are auto-detected
./vercel-bulk-waf-rules.sh show
```

### Option 2: API Token (Required for CI/CD)

For CI/CD pipelines or when you can't use interactive login:

```bash
export VERCEL_TOKEN="your-vercel-api-token"
export PROJECT_ID="prj_xxxxxxxxxxxx"
export TEAM_ID="team_xxxxxxxxxxxx"  # Optional, for team projects

./vercel-bulk-waf-rules.sh show
```

## Creating a Vercel API Token

1. Go to [vercel.com/account/tokens](https://vercel.com/account/tokens)
   - Make sure you're under **Personal Account** (not Teams) in the top-left dropdown
2. Click **Create** to open the token creation modal
3. Enter a descriptive name (e.g., "WAF Rules Script")
4. Click **Create Token**
5. **Choose the scope** from the dropdown:
   - Select your **Personal Account** for personal projects
   - Select a **specific Team** for team projects
6. **Copy the token immediately** — it will not be shown again

```bash
export VERCEL_TOKEN="your-token-here"
```

## Required Token Permissions

Your token needs these permissions based on how you created it:

| Scope | Required For | Description |
|-------|--------------|-------------|
| Personal Account | Personal projects | Full access to your personal projects |
| Team Scope | Team projects | Access to projects within that team |

> **Note:** Vercel tokens inherit permissions based on your account role. If you're a team member, your token can access team resources you have permission to modify.

## Finding Your Project ID

### Method 1: From the Vercel Dashboard

1. Go to [vercel.com/dashboard](https://vercel.com/dashboard)
2. Click on your project
3. Go to **Settings** → **General**
4. Scroll down to find **Project ID** (starts with `prj_`)

### Method 2: From `.vercel/project.json` (Recommended)

If you've run `vercel link` in your project directory:

```bash
cat .vercel/project.json
```

Output:

```json
{
  "projectId": "prj_xxxxxxxxxxxxxxxxxxxx",
  "orgId": "team_xxxxxxxxxxxxxxxxxxxx"
}
```

The script **automatically reads this file** if you run it from your project directory.

### Method 3: From the URL

When viewing your project in the dashboard, the URL contains the project name:

```
https://vercel.com/your-team/your-project-name/settings
```

You can use the project name instead of the ID with the API.

### Method 4: Via API

```bash
# List all projects
curl -s "https://api.vercel.com/v9/projects" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '.projects[] | {id, name}'

# For team projects, add teamId
curl -s "https://api.vercel.com/v9/projects?teamId=team_xxx" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '.projects[] | {id, name}'
```

## Finding Your Team ID

### Method 1: From the Dashboard

1. Click your team name in the top-left dropdown
2. Go to **Settings** → **General**
3. Scroll down to **Team ID** (starts with `team_`)

Or navigate directly to:

```
https://vercel.com/teams/your-team-name/settings
```

### Method 2: From `.vercel/project.json`

```bash
cat .vercel/project.json | jq '.orgId'
```

The `orgId` field is your Team ID (for team projects) or your user ID (for personal projects).

### Method 3: Via API

```bash
curl -s "https://api.vercel.com/v2/teams" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '.teams[] | {id, name, slug}'
```

## Quick Setup Summary

### Auto-detect (Recommended)

If you've already linked your project with Vercel CLI:

```bash
cd /path/to/your/vercel/project  # Directory with .vercel/project.json
export VERCEL_TOKEN="your-token"
./vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

### Manual Setup

```bash
export VERCEL_TOKEN="your-token"
export PROJECT_ID="prj_xxxxxxxxxxxx"
export TEAM_ID="team_xxxxxxxxxxxx"  # Only for team projects
./vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

### Guided Setup

```bash
./vercel-bulk-waf-rules.sh setup
```

## Verifying Your Credentials

Test that your credentials work:

```bash
# Test token validity
curl -s "https://api.vercel.com/v2/user" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '{username, email}'

# Test project access
curl -s "https://api.vercel.com/v9/projects/$PROJECT_ID?teamId=$TEAM_ID" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | jq '{id, name}'

# Or use the script's show command
./vercel-bulk-waf-rules.sh show
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `VERCEL_TOKEN environment variable is not set` | Token not exported | Run `export VERCEL_TOKEN="your-token"` |
| `HTTP 401 Unauthorized` | Invalid or expired token | Create a new token at vercel.com/account/tokens |
| `HTTP 403 Forbidden` | Token lacks team access | Recreate token with correct team scope |
| `HTTP 404 Not Found` | Wrong PROJECT_ID or TEAM_ID | Verify IDs from dashboard or `.vercel/project.json` |
| `Project not found` | Missing TEAM_ID for team project | Add `export TEAM_ID="team_xxx"` |

## Token Security Best Practices

- **Never commit tokens** to version control
- **Use environment variables** or a secrets manager
- **Scope tokens minimally** — use team-specific tokens when possible
- **Rotate tokens regularly** — especially after team member departures
- **Use short-lived tokens** for CI/CD when possible

For CI/CD, store tokens as secrets:

- **GitHub Actions**: Repository Settings → Secrets → `VERCEL_TOKEN`
- **GitLab CI**: Settings → CI/CD → Variables → `VERCEL_TOKEN`
- **CircleCI**: Project Settings → Environment Variables
