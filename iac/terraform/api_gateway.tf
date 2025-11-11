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

# 4b. Mock integration for OPTIONS method (CORS preflight)
resource "aws_api_gateway_integration" "options_integration" {
  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  resource_id = aws_api_gateway_resource.scan_resource.id
  http_method = aws_api_gateway_method.scan_options_method.http_method
  type        = "MOCK"
}

# 4c. Method response for OPTIONS
resource "aws_api_gateway_method_response" "options_200_response" {
  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  resource_id = aws_api_gateway_resource.scan_resource.id
  http_method = aws_api_gateway_method.scan_options_method.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

# 4d. Integration response for OPTIONS (setting the actual header values)
resource "aws_api_gateway_integration_response" "options_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  resource_id = aws_api_gateway_resource.scan_resource.id
  http_method = aws_api_gateway_method.scan_options_method.http_method
  status_code = aws_api_gateway_method_response.options_200_response.status_code

  response_templates = {
    "application/json" = ""
  }

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }

  depends_on = [aws_api_gateway_integration.options_integration]
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
      aws_api_gateway_integration.options_integration.id,
      aws_api_gateway_method_response.options_200_response.id,
      aws_api_gateway_integration_response.options_integration_response.id,
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
