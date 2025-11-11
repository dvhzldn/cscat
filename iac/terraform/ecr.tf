# Define the AWS provider configuration
provider "aws" {
  region = var.aws_region
}

# 1. Resource for the ECR Repository
resource "aws_ecr_repository" "scanner_repository" {
  name                 = "${var.project_name}-scanner-repository-261111"
  image_tag_mutability = "IMMUTABLE" # Enforces best practice: prevents image tags from being overwritten

  # Enable basic image scanning on push for an additional security check
  # This uses AWS's basic image vulnerability scanning
  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# 2. Resource for the Report S3 Bucket
resource "aws_s3_bucket" "report_bucket" {
  bucket = "${var.project_name}-security-reports-261111" # S3 bucket names must be globally unique
  acl    = "private"

  versioning {
    enabled = true # Best practice for protecting reports from accidental deletion/overwrites
  }

  server_side_encryption configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256" # Use S3-managed encryption, which is free
      }
    }
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# 3. Output the ECR Repository URI for the CI/CD pipeline
output "ecr_repository_uri" {
  description = "The URI of the ECR repository"
  value       = aws_ecr_repository.scanner_repository.repository_url
}

# 4. Output the S3 Bucket Name for the Lambda function
output "report_bucket_name" {
  description = "The name of the S3 bucket for storing reports"
  value       = aws_s3_bucket.report_bucket.bucket
}
