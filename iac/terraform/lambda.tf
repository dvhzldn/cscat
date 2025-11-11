data "archive_file" "placeholder" {
  type        = "zip"
  source_content_filename = "index.py"
  source_content = "def handler(event, context): return 'Initializing'"
  output_path = "${path.module}/placeholder.zip"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-${var.environment}-lambda-role"

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

resource "aws_iam_role_policy" "lambda_permissions_policy" {
  name = "${var.project_name}-${var.environment}-permissions"
  role = aws_iam_role.lambda_exec_role.id

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
        Resource = [
          aws_s3_bucket.report_bucket.arn,
          "${aws_s3_bucket.report_bucket.arn}/*",
        ]
      },
    ]
  })
}

resource "aws_lambda_function" "scanner_function" {
  function_name = "${var.project_name}-${var.environment}-scanner"
  role          = aws_iam_role.lambda_exec_role.arn

  package_type  = "Zip"
  runtime       = "python3.9"
  handler       = "index.handler"

  filename         = data.archive_file.placeholder.output_path
  source_code_hash = data.archive_file.placeholder.output_base64sha256

  timeout       = 30
  memory_size   = 128

  environment {
    variables = {
      REPORT_BUCKET_NAME = aws_s3_bucket.report_bucket.bucket
    }
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_rule" "schedule_rule" {
  name                = "${var.project_name}-${var.environment}-schedule"
  description         = "Triggers the security check every Monday at 10:00 AM UTC."
  schedule_expression = "cron(0 10 ? * MON *)"

  tags = {
    Project = var.project_name
  }
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.schedule_rule.name
  target_id = "scanner-lambda-target"
  arn       = aws_lambda_function.scanner_function.arn
}

resource "aws_lambda_permission" "allow_cloudwatch_to_invoke_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner_function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule_rule.arn
}

resource "aws_lambda_permission" "apigw_lambda_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_api_gateway_rest_api.scanner_api.execution_arn}/*/*"
}
