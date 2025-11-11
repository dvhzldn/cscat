# 1. API Gateway resource
resource "aws_api_gateway_rest_api" "scanner_api" {
  name        = "CSCATScannerAPI"
  description = "API Gateway for triggering the on-demand security scanner lambda."
}

# 2. Resource path (/scan)
resource "aws_api_gateway_resource" "scan_resource" {
  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  parent_id   = aws_api_gateway_rest_api.scanner_api.root_resource_id
  path_part   = "scan"
}

resource "aws_api_gateway_method" "scan_method" {
  rest_api_id   = aws_api_gateway_rest_api.scanner_api.id
  resource_id   = aws_api_gateway_resource.scan_resource.id
  http_method   = "POST"
  authorization = "NONE" # Matching the authorization level
}

# 3. Method to allow POST and OPTIONS requests to /scan
resource "aws_api_gateway_method" "scan_post_method" {
  rest_api_id   = aws_api_gateway_rest_api.scanner_api.id
  resource_id   = aws_api_gateway_resource.scan_resource.id
  http_method   = "POST"
  authorization = "NONE"
  api_key_required = false
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_method" "scan_options_method" {
  rest_api_id      = aws_api_gateway_rest_api.scanner_api.id
  resource_id      = aws_api_gateway_resource.scan_resource.id
  http_method      = "OPTIONS"
  authorization    = "NONE"
  lifecycle {
    create_before_destroy = true
  }
}

# 4. Integration with Lambda
resource "aws_api_gateway_integration" "lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.scanner_api.id
  resource_id             = aws_api_gateway_resource.scan_resource.id
  http_method             = aws_api_gateway_method.scan_post_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.scanner_function.invoke_arn
}

# 5. Deployment
resource "aws_api_gateway_deployment" "scanner_deployment" {
  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_rest_api.scanner_api.id,
      aws_api_gateway_resource.scan_resource.id,
      aws_api_gateway_method.scan_post_method.id,
      aws_api_gateway_method.scan_options_method.id,
      aws_api_gateway_integration.lambda_integration.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# 6. Stage definition (callable URL)
resource "aws_api_gateway_stage" "prod" {
  deployment_id = aws_api_gateway_deployment.scanner_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.scanner_api.id
  stage_name    = "prod"
}

# 7. URL for frontend to use
output "api_gateway_url" {
  description = "The base URL for the API Gateway stage"
  value       = aws_api_gateway_stage.prod.invoke_url
}
