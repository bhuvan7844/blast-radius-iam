resource "aws_iam_role" "role1" {
  name = "role1"
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
    name = "policy1"
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:PassRole",
    "Resource": "arn:aws:iam::123456789012:role/role2"
  }]
}
POLICY
  }
}

resource "aws_iam_role" "role2" {
  name = "role2"
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
    name = "policy2"
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:PassRole",
    "Resource": "arn:aws:iam::123456789012:role/role3"
  }]
}
POLICY
  }
}

resource "aws_iam_role" "role3" {
  name = "role3"
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
    name = "policy3"
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:PassRole",
    "Resource": "arn:aws:iam::123456789012:role/role4"
  }]
}
POLICY
  }
}

resource "aws_iam_role" "role4" {
  name = "role4"
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
    name = "policy4"
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

resource "aws_iam_role" "shortcut_role" {
  name = "shortcut-role"
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
    name = "shortcut_policy"
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

resource "aws_db_instance" "prod-db" {
  # placeholder for resource identification
}

