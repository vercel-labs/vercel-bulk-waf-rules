# CI/CD Integration

This guide covers how to integrate the Vercel Bulk WAF Rules scripts into your CI/CD pipelines.

> **Important:** In CI/CD (non-interactive) environments, `RULE_MODE` must be set explicitly. The script will not prompt and will error if the mode is not specified.

## GitHub Actions

See [`examples/github-action.yml`](../examples/github-action.yml) for a complete workflow that:

- Validates configurations on pull requests
- Applies changes on merge to main
- Supports manual dry-run triggers

### Setup

1. Add secrets: `VERCEL_TOKEN`
2. Add variables: `VERCEL_PROJECT_ID`, `VERCEL_TEAM_ID` (optional), `RULE_MODE` (required)
3. Copy the workflow file to `.github/workflows/`

### Example Workflow

```yaml
name: Vercel WAF Rules

on:
  push:
    branches: [main]
    paths:
      - 'vendor-ips.csv'
  pull_request:
    paths:
      - 'vendor-ips.csv'
  workflow_dispatch:
    inputs:
      dry_run:
        description: 'Dry run mode'
        required: false
        default: 'true'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y jq bc
          npm i -g vercel
      
      - name: Validate CSV
        env:
          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
          PROJECT_ID: ${{ vars.VERCEL_PROJECT_ID }}
          TEAM_ID: ${{ vars.VERCEL_TEAM_ID }}
          RULE_MODE: ${{ vars.RULE_MODE || 'bypass' }}
        run: |
          DRY_RUN=true ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

  deploy:
    needs: validate
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y jq bc
          npm i -g vercel
      
      - name: Apply WAF Rules
        env:
          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
          PROJECT_ID: ${{ vars.VERCEL_PROJECT_ID }}
          TEAM_ID: ${{ vars.VERCEL_TEAM_ID }}
          RULE_MODE: ${{ vars.RULE_MODE || 'bypass' }}
          AUDIT_LOG: ./waf-audit.log
        run: |
          echo "yes" | ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
      
      - name: Upload Audit Log
        uses: actions/upload-artifact@v4
        with:
          name: waf-audit-log
          path: ./waf-audit.log
```

## GitLab CI

```yaml
stages:
  - validate
  - deploy

variables:
  RULE_MODE: bypass

.setup: &setup
  before_script:
    - apt-get update && apt-get install -y jq bc curl
    - npm i -g vercel

validate:
  <<: *setup
  stage: validate
  script:
    - DRY_RUN=true ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - vendor-ips.csv

deploy:
  <<: *setup
  stage: deploy
  script:
    - echo "yes" | ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      changes:
        - vendor-ips.csv
  environment:
    name: production
```

**GitLab CI Variables to set:**

- `VERCEL_TOKEN` (masked)
- `PROJECT_ID`
- `TEAM_ID` (optional)
- `RULE_MODE`

## CircleCI

```yaml
version: 2.1

jobs:
  validate:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run:
          name: Install dependencies
          command: |
            sudo apt-get update && sudo apt-get install -y jq bc
            npm i -g vercel
      - run:
          name: Validate WAF Rules
          command: |
            DRY_RUN=true ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

  deploy:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run:
          name: Install dependencies
          command: |
            sudo apt-get update && sudo apt-get install -y jq bc
            npm i -g vercel
      - run:
          name: Apply WAF Rules
          command: |
            echo "yes" | ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

workflows:
  version: 2
  waf-rules:
    jobs:
      - validate
      - deploy:
          requires:
            - validate
          filters:
            branches:
              only: main
```

**CircleCI Environment Variables to set:**

- `VERCEL_TOKEN`
- `PROJECT_ID`
- `TEAM_ID` (optional)
- `RULE_MODE`

## Azure DevOps

```yaml
trigger:
  branches:
    include:
      - main
  paths:
    include:
      - vendor-ips.csv

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: Validate
    jobs:
      - job: ValidateRules
        steps:
          - script: |
              sudo apt-get update && sudo apt-get install -y jq bc
              npm i -g vercel
            displayName: 'Install dependencies'
          
          - script: |
              DRY_RUN=true ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
            displayName: 'Validate WAF rules'
            env:
              VERCEL_TOKEN: $(VERCEL_TOKEN)
              PROJECT_ID: $(PROJECT_ID)
              TEAM_ID: $(TEAM_ID)
              RULE_MODE: $(RULE_MODE)

  - stage: Deploy
    dependsOn: Validate
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: DeployRules
        environment: 'production'
        strategy:
          runOnce:
            deploy:
              steps:
                - checkout: self
                
                - script: |
                    sudo apt-get update && sudo apt-get install -y jq bc
                    npm i -g vercel
                  displayName: 'Install dependencies'
                
                - script: |
                    echo "yes" | ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
                  displayName: 'Apply WAF rules'
                  env:
                    VERCEL_TOKEN: $(VERCEL_TOKEN)
                    PROJECT_ID: $(PROJECT_ID)
                    TEAM_ID: $(TEAM_ID)
                    RULE_MODE: $(RULE_MODE)
```

## AWS CodePipeline / CodeBuild

**buildspec.yml:**

```yaml
version: 0.2

env:
  secrets-manager:
    VERCEL_TOKEN: arn:aws:secretsmanager:us-east-1:123456789:secret:vercel-token

phases:
  install:
    commands:
      - apt-get update && apt-get install -y jq bc
      - npm i -g vercel
  
  pre_build:
    commands:
      - echo "Validating WAF rules..."
      - DRY_RUN=true ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
  
  build:
    commands:
      - echo "Applying WAF rules..."
      - echo "yes" | ./vercel-bulk-waf-rules.sh apply vendor-ips.csv

artifacts:
  files:
    - waf-audit.log
```

## Generic CI/CD Template

For any CI/CD system, follow this pattern:

```bash
#!/bin/bash
set -euo pipefail

# Required environment variables (set as secrets/variables in your CI)
: "${VERCEL_TOKEN:?VERCEL_TOKEN is required}"
: "${PROJECT_ID:?PROJECT_ID is required}"
: "${RULE_MODE:?RULE_MODE must be 'deny' or 'bypass'}"

# Optional
TEAM_ID="${TEAM_ID:-}"
CSV_FILE="${CSV_FILE:-vendor-ips.csv}"
DRY_RUN="${DRY_RUN:-false}"

# Export for the script
export VERCEL_TOKEN PROJECT_ID TEAM_ID RULE_MODE

# Install dependencies
apt-get update && apt-get install -y jq bc curl
npm i -g vercel

# Validate
echo "=== Validating WAF rules ==="
DRY_RUN=true ./vercel-bulk-waf-rules.sh apply "$CSV_FILE"

# Apply (only if not dry run and validation passed)
if [ "$DRY_RUN" != "true" ]; then
    echo "=== Applying WAF rules ==="
    echo "yes" | ./vercel-bulk-waf-rules.sh apply "$CSV_FILE"
fi
```

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `VERCEL_TOKEN` | Yes | Vercel API token (store as secret) |
| `PROJECT_ID` | Yes* | Vercel project ID (*auto-detected if `.vercel/project.json` exists) |
| `TEAM_ID` | No | Vercel team ID (for team projects) |
| `RULE_MODE` | Yes | Must be `deny` or `bypass` in CI/CD |
| `DRY_RUN` | No | Set to `true` for validation only |
| `AUDIT_LOG` | No | Path to audit log file |
| `DEBUG` | No | Set to `true` for verbose output |

## Confirmation Bypass

The script requires interactive confirmation. In CI/CD, pipe `yes` to bypass:

```bash
echo "yes" | ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

Or for purge operations:

```bash
echo "PURGE" | ./vercel-bulk-waf-rules.sh purge
```

## Best Practices

### 1. Always Validate First

Run with `DRY_RUN=true` before applying:

```bash
DRY_RUN=true ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

### 2. Use Audit Logging

Enable audit logging for compliance:

```bash
AUDIT_LOG=./waf-audit.log ./vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

### 3. Create Backups Before Changes

```bash
./vercel-bulk-waf-rules.sh backup
./vercel-bulk-waf-rules.sh apply vendor-ips.csv
```

### 4. Use Separate Tokens

Create dedicated API tokens for CI/CD with minimal permissions.

### 5. Pin Dependencies

Use specific versions to ensure reproducibility:

```bash
npm i -g vercel@50.7.1
```

### 6. Handle Failures Gracefully

```bash
if ! ./vercel-bulk-waf-rules.sh apply vendor-ips.csv; then
    echo "Failed to apply WAF rules"
    # Notify on-call, create incident, etc.
    exit 1
fi
```

### 7. Use Branch Protection

- Require PR reviews for changes to `vendor-ips.csv`
- Run validation on all PRs
- Only deploy from protected branches

## Rollback in CI/CD

If something goes wrong, you can disable or restore rules:

```bash
# Disable all rules (allows all traffic)
echo "yes" | ./vercel-bulk-waf-rules.sh disable

# Or remove completely
echo "PURGE" | ./vercel-bulk-waf-rules.sh purge

# Or restore from backup
./rollback.sh restore backups/backup-prj_xxx-20240115-143000.json
```

## Monitoring

Consider adding monitoring after deployment:

```bash
# After applying rules
./vercel-bulk-waf-rules.sh show

# Check rule count
RULE_COUNT=$(./vercel-bulk-waf-rules.sh show 2>&1 | grep -c "Rule:")
echo "Deployed $RULE_COUNT WAF rules"
```
