# SchoolCloud Portal

_A secure, serverless portal for schools built on AWS — designed as a hands-on demonstration of cloud security and architecture concepts._

Live site: https://portal.secureschoolcloud.org  

SchoolCloud is a reference architecture for a **secure AWS serverless environment** aimed at K–12 and higher education. I designed and implemented it end-to-end to show how I approach real-world cloud security, reliability, and DevSecOps on AWS.

The platform brings together:

- **CloudFront + WAF + S3** at the edge for secure content delivery  
- **Cognito** for identity and authentication  
- **API Gateway + Lambda + DynamoDB** for scalable, serverless application logic and data  
- **CloudTrail, Config, GuardDuty, Security Hub, IAM Access Analyzer, and Macie** for deep security visibility and detection  
- **Terraform + GitHub Actions (OIDC)** for infrastructure-as-code, automated deployments, and CI/CD security checks  

From a **user’s** perspective, it’s a simple portal where students, teachers, and admins can manage profiles and view activity. From a **hiring manager’s** perspective, it’s a realistic, end-to-end example of how I architect, secure, and operate serverless workloads on AWS using modern DevSecOps practices.
---

## Features

### User-facing features

The site is organized into five main pages, all behind Cognito sign-in: :contentReference[oaicite:2]{index=2}

- **Home** (`index.html`)  
  High-level overview of the portal, the AWS services behind it, and guidance to sign in and explore Profile, Activity, Security Lab, Security Overview, and CI/CD views.

- **My Profile** (`profile.html`)  
  - Shows the signed-in user’s **role** (Student / Teacher / Administrator) and email.  
  - Lets the user choose a role and edit a free-form **bio**, then save changes.  
  - Profile data is stored in an encrypted **DynamoDB** table and changes are audited with **CloudTrail**. :contentReference[oaicite:3]{index=3}  

- **Activity & Logs** (`activity.html`)  
  - Displays the currently signed-in user and API status.  
  - Lets the user pick a time window (last 15–120 minutes) and auto-refresh interval.  
  - Shows:
    - **Security events (CloudTrail)** – sign-in and other security events for the portal  
    - **My recent actions** – audit entries like `PROFILE_READ` and `PROFILE_UPDATE` from the profile Lambda, filtered per-user  
  - Includes a “Raw response” debug view for the full JSON returned by the activity API. :contentReference[oaicite:4]{index=4}  

- **Security Lab** (`risk-lab.html`)  
  A hands-on **PII risk lab** that demonstrates how local pattern-matching and Amazon Macie work together:
  1. When you save your profile, the bio is stored in DynamoDB and a full copy of the profile JSON is written to an encrypted S3 bucket.  
  2. A **local PII scanner Lambda** runs off a DynamoDB Stream and scans just the bio text for simple patterns like DOBs or test SSNs, then writes findings to a “findings” table.  
  3. An **Amazon Macie job** scans the encrypted S3 bucket containing full profile snapshots for richer sensitive data types.  
  4. A **Macie ingest Lambda** subscribes to Macie findings via EventBridge, normalizes them, and inserts them into the same findings table.  
  5. The Security Lab UI calls a secured API to fetch **your findings**, clearly labeling `Source: Local scan` vs `Source: Macie`.  
  It also shows a “Macie activity” panel so you can see when Macie has recently produced findings. :contentReference[oaicite:5]{index=5}  

- **Security Overview** (`security-overview.html`)  
  - Admin-only dashboard that will display a read-only snapshot of key AWS security services backing the portal.  
  - Signals include CloudTrail, GuardDuty, Security Hub, Config, WAF, and encryption posture. :contentReference[oaicite:6]{index=6}  

- **CI/CD Pipeline** (`cicd-pipeline.html`)  
  - Explains how GitHub Actions, Terraform, and AWS OIDC are wired together.  
  - Documents the Terraform Plan, Security Scan, and Deploy workflows.  
  - Shows architecture and screenshots of real workflow runs (plan, deploy, and tfsec/checkov scans). :contentReference[oaicite:7]{index=7}  


---

## Architecture

**Edge / Web layer**

- **Amazon CloudFront** distribution in front of:
  - **S3 static website bucket** for all HTML, JS, and assets
  - **Amazon API Gateway HTTP APIs** for profile, activity, findings/PII lab, and security posture data
- **AWS WAF** attached to CloudFront with:
  - Managed rulesets
  - Custom rules and rate limits (e.g., blocking `/wp-admin`-style paths)
- **CloudFront Function** for strict security headers:
  - HSTS
  - CSP (self + API origin)
  - X-Content-Type-Options, X-Frame-Options, Referrer-Policy

**Identity**

- **Amazon Cognito User Pool** with:
  - Hosted UI and OAuth2 authorization code flow
  - Strong password policies and email verification
- **Cognito App Client** configured with callbacks under `portal.secureschoolcloud.org`
- **JWT-based auth** on API Gateway routes, including per-user scoping of logs and findings

**Application & Data**

- **Profile Lambda** (`profile_handler`):
  - CRUD for user profile (role, bio, metadata) in **DynamoDB**  
  - Emits structured `PROFILE_READ` / `PROFILE_UPDATE` events to CloudWatch Logs  

- **Activity Lambda** (`telemetry_handler`):
  - Queries CloudWatch Logs for recent profile events per user  
  - Queries **CloudTrail** for recent security events for this portal  
  - Returns a combined JSON payload shown on the Activity & Logs page  

- **PII Local Scan Lambda**:
  - Triggered by **DynamoDB Streams** on the profiles table  
  - Runs simple pattern-based checks (DOB, SSN, etc.) on the bio text  
  - Writes normalized findings into a **findings DynamoDB table**  

- **Macie Ingest Lambda**:
  - Subscribed to **EventBridge** for Amazon Macie findings on the S3 profile snapshots bucket  
  - Normalizes Macie findings into the same findings table used by the local scanner  

- **Security Overview Lambda (admin)**:
  - Aggregates a read-only snapshot of:
    - CloudTrail logging status
    - GuardDuty and Security Hub findings
    - AWS Config compliance summaries
    - WAF metrics
    - Encryption posture (e.g., KMS-backed tables, S3 default encryption)

- **Data stores & encryption**:
  - **DynamoDB**:
    - Profiles table (per-user profile data)
    - Findings table (per-user PII and Macie findings)
  - **KMS CMK** for table encryption and selected app secrets  
  - Encrypted **S3** bucket for profile JSON snapshots used by Macie  

**Security & Governance**

- **AWS CloudTrail** (multi-region) for full audit logs  
- **AWS Config** for resource configuration tracking and rules (e.g., S3 public access)  
- **GuardDuty**, **Security Hub**, **IAM Access Analyzer** for detection and analysis  
- **EventBridge + SNS** for security alerts (e.g., root usage, IAM changes, CloudTrail tampering)  
- IAM permission boundaries to constrain CI/CD and application roles to least privilege  

All infrastructure is described and deployed via **Terraform modules** (e.g., `foundations`, `network`, `edge`, `identity`, `data`, `app_profile`, `app_telemetry`, `cicd_iam`) under `infra/`, with GitHub Actions assuming a dedicated deploy role via OIDC. :contentReference[oaicite:10]{index=10}  


---

## Repository layout (high level)

> Directory names may evolve, but this is the intended structure of the project.

```text
.
├── infra/                  # Terraform IaC
│   ├── main.tf
│   ├── backend.tf          # S3 + DynamoDB remote state
│   ├── providers.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── modules/
│       ├── foundations/    # CloudTrail, Config, GuardDuty, SecHub, Access Analyzer, logs
│       ├── network/        # VPC, subnets, endpoints, security groups
│       ├── edge/           # S3 web, CloudFront, WAF, certs, Route 53
│       ├── identity/       # Cognito User Pool, App Client, domain
│       ├── data/           # DynamoDB tables, KMS keys, parameters
│       ├── app_profile/    # Profile Lambda, API routes, IAM
│       ├── app_telemetry/  # Activity Lambda, API routes, IAM
│       ├── app_findings/   # Local PII + Macie ingest Lambdas, findings API
│       └── cicd_iam/       # GitHub OIDC provider, deploy role, permission boundary
├── apps/
│   ├── web/
│   │   ├── index.html
│   │   ├── profile.html
│   │   ├── activity.html
│   │   ├── risk-lab.html
│   │   ├── security-overview.html
│   │   └── cicd-pipeline.html
│   └── lambda/
│       ├── profile_handler.py
│       ├── telemetry_handler.py
│       ├── pii_scanner.py
│       └── macie_ingest.py
├── .github/
│   └── workflows/
│       ├── terraform-plan.yml
│       ├── terraform-deploy.yml
│       └── security-scan.yml
└── docs/
    ├── architecture.md
    ├── threat-model.md
    ├── security-highlights.md
    └── multi-account-strategy.md


