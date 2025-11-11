resource "aws_api_gateway_rest_api" "scanner_api" {
  name        = "CSCATScannerAPI"
  description = "API Gateway for triggering the on-demand security scanner lambda."
}

locals {
  cors_headers = {
    "gatewayresponse.header.Access-Control-Allow-Origin"  = "'*'"
    "gatewayresponse.header.Access-Control-Allow-Methods" = "'POST,OPTIONS'"
    "gatewayresponse.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,Sec-Ch-Ua-Platform,Dnt'"
  }
}

# Global 4xx/5xx CORS-enabled responses
resource "aws_api_gateway_gateway_response" "default_5xx_response" {
  rest_api_id        = aws_api_gateway_rest_api.scanner_api.id
  response_type      = "DEFAULT_5XX"
  response_parameters = local.cors_headers
}

resource "aws_api_gateway_gateway_response" "default_4xx_response" {
  rest_api_id        = aws_api_gateway_rest_api.scanner_api.id
  response_type      = "DEFAULT_4XX"
  response_parameters = local.cors_headers
}

# --- API Resources ---
resource "aws_api_gateway_resource" "resources" {
  for_each = {
    scan        = "scan"
    dns         = "dns"
    fingerprint = "fingerprint"
  }

  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  parent_id   = aws_api_gateway_rest_api.scanner_api.root_resource_id
  path_part   = each.value

  lifecycle {
  prevent_destroy = true
  }
}

# --- POST Methods (Lambda Proxy) ---
resource "aws_api_gateway_method" "post_method" {
  for_each = aws_api_gateway_resource.resources

  rest_api_id   = aws_api_gateway_rest_api.scanner_api.id
  resource_id   = each.value.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "post_integration" {
  for_each = aws_api_gateway_method.post_method

  rest_api_id             = aws_api_gateway_rest_api.scanner_api.id
  resource_id             = each.value.resource_id
  http_method             = each.value.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"

  uri = "arn:aws:apigateway:${var.aws_region}:lambda:path/2015-03-31/functions/${lookup(
    {
      scan        = aws_lambda_function.scanner_function.arn,
      dns         = aws_lambda_function.dns_scanner_function.arn,
      fingerprint = aws_lambda_function.fingerprint_scanner_function.arn
    },
    each.key
  )}/invocations"
}

# --- OPTIONS (Mock Integration for CORS) ---
resource "aws_api_gateway_method" "options_method" {
  for_each = aws_api_gateway_resource.resources

  rest_api_id   = aws_api_gateway_rest_api.scanner_api.id
  resource_id   = each.value.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "options_integration" {
  for_each = aws_api_gateway_method.options_method

  rest_api_id             = aws_api_gateway_rest_api.scanner_api.id
  resource_id             = each.value.resource_id
  http_method             = each.value.http_method
  type                    = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\":200}"
  }
}

resource "aws_api_gateway_method_response" "options_response" {
  for_each = aws_api_gateway_method.options_method

  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  resource_id = each.value.resource_id
  http_method = each.value.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "options_integration_response" {
  for_each = aws_api_gateway_integration.options_integration

  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  resource_id = each.value.resource_id
  http_method = each.value.http_method
  status_code = aws_api_gateway_method_response.options_response[each.key].status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,Sec-Ch-Ua-Platform,Dnt'"
    "method.response.header.Access-Control-Allow-Methods" = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

# --- Deployment ---
resource "aws_api_gateway_deployment" "scanner_deployment" {
  rest_api_id = aws_api_gateway_rest_api.scanner_api.id
  description = "Deployment at ${timestamp()}"

  triggers = {
    redeploy_hash = sha1(jsonencode([
      aws_api_gateway_resource.resources,
      aws_api_gateway_method.post_method,
      aws_api_gateway_integration.post_integration,
      aws_api_gateway_method.options_method,
      aws_api_gateway_integration.options_integration
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.scanner_api.id
  deployment_id = aws_api_gateway_deployment.scanner_deployment.id
  stage_name    = "prod"
  description   = "Production Stage"
}

output "api_gateway_url" {
  description = "The base URL for the API Gateway stage"
  value       = aws_api_gateway_stage.prod.invoke_url
}
