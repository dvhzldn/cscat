terraform {
  backend "s3" {
    key            = "cscat/terraform.tfstate"
    region         = "eu-west-2"
    encrypt        = true
  }
}
