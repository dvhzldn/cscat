# --- IAM Role and Policy (Least Privilege) ---

# 1. IAM Role for the Lambda function
resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-${var.environment}-lambda-role"

  # Trust policy allowing the Lambda service to assume the role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Project = var.project_name
  }
}

# 2. IAM Policy for CloudWatch Logs and S3 Access
resource "aws_iam_role_policy" "lambda_permissions_policy" {
  name = "${var.project_name}-${var.environment}-permissions"
  role = aws_iam_role.lambda_exec_role.id

  # Policy granting minimum permissions: CloudWatch Logging and S3 R/W on the report bucket
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*:*"
      },
      {
        Sid    = "AllowS3ReportAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
        ]
        # Scope access ONLY to the report bucket created in ecr.tf
        Resource = [
          aws_s3_bucket.report_bucket.arn,
          "${aws_s3_bucket.report_bucket.arn}/*",
        ]
      },
    ]
  })
}

# Data source to retrieve the current AWS account ID for ARN construction
data "aws_caller_identity" "current" {}


# --- AWS Lambda Function ---

# 3. The Lambda function resource
resource "aws_lambda_function" "scanner_function" {
  function_name = "${var.project_name}-${var.environment}-scanner"
  role          = aws_iam_role.lambda_exec_role.arn
  # Use Container Image package type
  package_type  = "Image"
  # Use the ECR image URI output from the previous phase
  image_uri     = aws_ecr_repository.scanner_repository.repository_url
  lifecycle {
    # Terraform will create the function, but will ignore any changes made to
    # the image_uri by external processes (like your CI/CD's aws lambda update-function-code).
    ignore_changes = [
      image_uri,
    ]
  }
  # Set the timeout to 30 seconds (future scans may be longer)
  timeout       = 30
  memory_size   = 128 # Default memory size is cost-effective and should suffice for HTTP checks

  # Handler is optional when using a container image, but we'll specify the one from the Dockerfile (app.lambda_handler)
  # as best practice for clarity.
  handler       = "app.lambda_handler"

  # --- NEW: Pass S3 Bucket Name as Environment Variable ---
  environment {
    variables = {
      REPORT_BUCKET_NAME = aws_s3_bucket.report_bucket.bucket
    }
  }
  # --- END NEW ---

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# --- Scheduling with AWS EventBridge ---

# 4. EventBridge Rule to define the schedule
resource "aws_cloudwatch_event_rule" "schedule_rule" {
  name                = "${var.project_name}-${var.environment}-schedule"
  description         = "Triggers the security check every Monday at 10:00 AM UTC."
  # Cron expression for 10:00 AM UTC, every Monday
  schedule_expression = "cron(0 10 ? * MON *)"

  tags = {
    Project = var.project_name
  }
}

# 5. EventBridge Target to link the rule to the Lambda function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.schedule_rule.name
  target_id = "scanner-lambda-target"
  arn       = aws_lambda_function.scanner_function.arn
}

# 6. Lambda Permission to allow EventBridge to invoke the function
resource "aws_lambda_permission" "allow_cloudwatch_to_invoke_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner_function.function_name
  # The principal is the service that is allowed to invoke the Lambda
  principal     = "events.amazonaws.com"
  # Source ARN scopes the permission to this specific EventBridge rule
  source_arn    = aws_cloudwatch_event_rule.schedule_rule.arn
}
