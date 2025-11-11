######################################################
# LAMBDA PLACEHOLDER ARCHIVES
######################################################
data "archive_file" "scanner_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../src/lambda_scanner"
  output_path = "${path.module}/scanner.zip"
}

data "archive_file" "dns_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../src/lambda_dns"
  output_path = "${path.module}/dns.zip"
}

data "archive_file" "fingerprint_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../src/lambda_fingerprint"
  output_path = "${path.module}/fingerprint.zip"
}

######################################################
# RANDOM SUFFIX FOR S3 BUCKET UNIQUENESS
######################################################
resource "random_id" "s3_suffix" {
  byte_length = 2
}

######################################################
# S3 BUCKET FOR LAMBDA DEPLOYMENT ARTIFACTS
######################################################
resource "aws_s3_bucket" "lambda_bucket" {
  bucket = "cscat-dev-lambda-artifacts-${random_id.s3_suffix.hex}"
  force_destroy = true
}

######################################################
# IAM ROLE AND POLICIES FOR LAMBDAS
######################################################
resource "aws_iam_role" "lambda_role" {
  name = "cscat-dev-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_s3_policy" {
  name        = "cscat-dev-lambda-s3-access-${random_id.s3_suffix.hex}"
  description = "Allow Lambda functions to access S3 and CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "logs:*",
          "lambda:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_s3_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_s3_policy.arn
}

######################################################
# LAMBDA FUNCTIONS
######################################################
resource "aws_lambda_function" "scanner_function" {
  function_name = "cscat-dev-scanner"
  role          = aws_iam_role.lambda_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  timeout       = 30

  filename         = data.archive_file.scanner_zip.output_path
  source_code_hash = data.archive_file.scanner_zip.output_base64sha256
}

resource "aws_lambda_function" "dns_scanner_function" {
  function_name = "cscat-dev-dns-scanner"
  role          = aws_iam_role.lambda_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  timeout       = 30

  filename         = data.archive_file.dns_zip.output_path
  source_code_hash = data.archive_file.dns_zip.output_base64sha256
}

resource "aws_lambda_function" "fingerprint_scanner_function" {
  function_name = "cscat-dev-fingerprint-scanner"
  role          = aws_iam_role.lambda_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  timeout       = 30

  filename         = data.archive_file.fingerprint_zip.output_path
  source_code_hash = data.archive_file.fingerprint_zip.output_base64sha256
}
