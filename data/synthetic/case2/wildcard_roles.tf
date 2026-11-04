resource "aws_iam_role" "wildcard_prod_role" {
  name = "wildcard-prod-role"
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
    name = "wildcard-prod-policy"
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "arn:aws:rds:::prod-customer-db"
  }]
}
POLICY
  }
}

