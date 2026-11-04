resource "aws_iam_role" "wildcard_dev_role" {
  name = "wildcard-dev-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": "sts:AssumeRole"
  }]
}
EOF
  inline_policy = {
    name = "wildcard-dev-policy"
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "arn:aws:s3:::dev-bucket/*"
  }]
}
POLICY
  }
}

