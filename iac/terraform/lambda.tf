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
  handler       = "index.lambda_handler"
  timeout       = 30

  filename         = data.archive_file.scanner_zip.output_path
  source_code_hash = data.archive_file.scanner_zip.output_base64sha256
}

resource "aws_lambda_function" "dns_scanner_function" {
  function_name = "cscat-dev-dns-scanner"
  role          = aws_iam_role.lambda_role.arn
  runtime       = "python3.12"
  handler       = "index.lambda_handler"
  timeout       = 30

  filename         = data.archive_file.dns_zip.output_path
  source_code_hash = data.archive_file.dns_zip.output_base64sha256
}

resource "aws_lambda_function" "fingerprint_scanner_function" {
  function_name = "cscat-dev-fingerprint-scanner"
  role          = aws_iam_role.lambda_role.arn
  runtime       = "python3.12"
  handler       = "index.lambda_handler"
  timeout       = 30

  filename         = data.archive_file.fingerprint_zip.output_path
  source_code_hash = data.archive_file.fingerprint_zip.output_base64sha256
}

######################################################
# ALLOW API GATEWAY TO INVOKE LAMBDAS
######################################################
locals {
  lambda_functions = {
    scan        = aws_lambda_function.scanner_function.function_name
    dns         = aws_lambda_function.dns_scanner_function.function_name
    fingerprint = aws_lambda_function.fingerprint_scanner_function.function_name
  }
}

resource "aws_lambda_permission" "api_gateway_invoke" {
  for_each = local.lambda_functions

  statement_id  = "AllowExecutionFromAPIGateway-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = each.value
  principal     = "apigateway.amazonaws.com"

  # Allow only the relevant API Gateway method/resource
  source_arn = "${aws_api_gateway_rest_api.scanner_api.execution_arn}/*/POST/${each.key}"

  # Ensure Lambda and API Gateway exist before adding permission
  depends_on = [
    aws_api_gateway_rest_api.scanner_api
  ]
}
