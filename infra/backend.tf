terraform {
  backend "s3" {
    bucket         = "ssp-tfstate-giovanna-73048814"
    key            = "portal/global.tfstate"
    region         = "us-east-1"
    dynamodb_table = "ssp-tf-locks"
    encrypt        = true
  }
}
