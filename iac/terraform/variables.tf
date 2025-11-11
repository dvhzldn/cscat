variable "aws_region" {
  description = "AWS region to deploy resources to"
  type        = string
  default     = "eu-west-2"
}

variable "project_name" {
  description = "For resource tagging and naming conventions"
  type        = string
  default     = "cscat"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
}
