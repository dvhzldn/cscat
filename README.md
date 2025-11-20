# Community Security Checkup Automation Tool (CSCAT)

## Project summary

The Community Security Checkup Automation Tool (CSCAT) is a fully serverless
application designed for on-demand web security auditing. It performs checks on
domain configurations, focusing on critical areas such as HTTP Security Headers,
DNS records and email authentication settings.

The entire infrastructure, from API Gateway to the Lambda execution environment,
is provisioned and managed declaratively using Terraform. A Continuous
Deployment (CD) pipeline is implemented via GitHub Actions to ensure idempotent
and reliable updates. This project serves as a demonstration of IaC and
DevSecOps principles.

## Live demo

[Link](https://cscat-security-reports-261111.s3.eu-west-2.amazonaws.com/index.html)

## Key features

### Security and auditing functionality

- **URL/Domain Scanner**: Accepts any public URL or domain name for analysis.

- **Customisable Checks**: Allows users to select or deselect specific security
  checks via front-end toggles ( DNS and HTTP Headers).

- **Real-time Results**: Displays scan results instantly, using clear Pass
  (Green) and Fail (Red) visual indicators.

- **Detailed Output**: Provides a dedicated section for full HTTP Response
  Headers and deep technical output for diagnosis.

- **Data Export**: Ability to export the complete scan results in a JSON format
  for external reporting or tooling.

### Architecture and Deployment

- **Infrastructure as Code (IaC)**: 100% of the AWS infrastructure is defined
  and managed by Terraform.

- **Lambda Functions**: Manages the deployment of three specialised Python
  Lambda functions (`scanner`, `dns`, `fingerprint`).

- **API Gateway**: Provisions the REST API with CORS-enabled endpoints to invoke
  the Lambda functions.

- **Decoupled Architecture**: Utilises three separate Python Lambda functions
  (Python 3.12, using dnspython and requests) to handle distinct scanning tasks,
  ensuring modularity and isolated scaling.

- **Durable State Management**: The Terraform state file is managed securely in
  a versioned and encrypted AWS S3 bucket, with state locking enforced by a
  DynamoDB table (`cscat-terraform-locks`) to prevent concurrent updates.

- **Static Frontend Hosting**: The front-end is a simple, lightweight HTML page
  hosted statically on a dedicated AWS S3 bucket.

## Technical architecture

This repository is structured around the IaC paradigm, where code defines the
infrastructure.

| Component         | Technology                       | IaC File                        | Role                                                           |
| ----------------- | -------------------------------- | ------------------------------- | -------------------------------------------------------------- |
| IaC Orchestration | Terraform (v1.9.5)               | `iac/terraform/*.tf`            | Provisions all AWS services.                                   |
| CI/CD Pipeline    | GitHub Actions                   | `.github/workflows/deploy.yml`  | Automates init, plan, apply, and Lambda code updates.          |
| Backend Compute   | AWS Lambda (Python)              | `src/lambda_*`                  | Executes domain security checks.                               |
| API Endpoint      | AWS API Gateway                  | `api_gateway.tf`                | Exposes the Lambda functions as REST endpoints (POST methods). |
| State Management  | AWS S3 & DynamoDB                | `bootstrap.tf`                  | Stores the remote Terraform state file and manages locking.    |
| Dependencies      | `dnspython`, `requests`, `boto3` | `src/lambda_*/requirements.txt` | Python packages for DNS querying and HTTP requests.            |

## Continuous Deployment Pipeline

The `deploy.yml` GitHub Actions workflow manages the entire CD process:

1. AWS Credentials: Assumes an IAM role (`GitHubActions-DevSecOps-Role`) using
   OIDC (OpenID Connect) for secure, temporary credential configuration.

2. Bootstrap: Checks for and creates the necessary S3 state bucket and DynamoDB
   lock table if they do not exist.

3. Terraform Workflow: Executes the standard `init`, `plan`, and
   `apply -auto-approve` commands in the `iac/terraform` directory.

4. Artifact Packaging: Locally packages each of the three Python Lambda
   functions and their dependencies into individual `.zip` files.

5. Frontend Update: Retrieves the live API Gateway URL from the Terraform
   outputs and injects it into the `index.html` frontend.

6. S3 Uploads: Uploads the packaged Lambda zips and the configured `index.html`
   to the dedicated S3 report bucket.

7. Lambda Code Update: Triggers `aws lambda update-function-code` commands to
   instantly deploy the new scanner logic to the existing functions provisioned
   by Terraform.

## Licence

This project is open-sourced under the MIT Licence.
