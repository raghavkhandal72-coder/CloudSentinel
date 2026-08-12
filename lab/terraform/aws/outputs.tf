output "vulnerable_bucket_name" {
  value = aws_s3_bucket.vulnerable_bucket.bucket
}

output "vulnerable_sg_id" {
  value = aws_security_group.vulnerable_sg.id
}

output "vulnerable_user_name" {
  value = aws_iam_user.vulnerable_user.name
}
