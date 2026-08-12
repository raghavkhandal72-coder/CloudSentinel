provider "aws" {
  region = var.region
}

# 1. Vulnerable S3 Bucket
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "cloudsentinel-vulnerable-bucket-${random_id.suffix.hex}"
  force_destroy = true
  
  tags = {
    Name        = "VulnerableBucket"
    Environment = "Lab"
  }
}

# Public access block explicitly disabled (allows public access)
resource "aws_s3_bucket_public_access_block" "vulnerable_bucket_public_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Public bucket policy allowing all read access
resource "aws_s3_bucket_policy" "allow_public_read" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      }
    ]
  })
  
  depends_on = [aws_s3_bucket_public_access_block.vulnerable_bucket_public_access]
}

# 2. Vulnerable Security Group (Open SSH and RDP)
resource "aws_vpc" "lab_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-web-sg"
  description = "Intentionally vulnerable security group for CloudSentinel lab"
  vpc_id      = aws_vpc.lab_vpc.id

  ingress {
    description = "Open SSH to the world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Open RDP to the world"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Overly Permissive IAM Policy & User
resource "aws_iam_user" "vulnerable_user" {
  name = "cloudsentinel-lab-user"
}

resource "aws_iam_user_policy_attachment" "admin_access" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "random_id" "suffix" {
  byte_length = 4
}
