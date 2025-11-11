terraform {
  backend "s3" {
    bucket         = "cscat-terraform-state-261111"
    key            = "terraform.tfstate"
    region         = "eu-west-2"
    dynamodb_table = "cscat-terraform-locks"
    encrypt        = true
  }
}
