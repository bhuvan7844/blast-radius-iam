resource "aws_iam_role" "dev_role" {
  name = "dev-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF
}

resource "aws_iam_policy" "wildcard_policy" {
  name   = "wildcard-policy"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.dev_role.name
  policy_arn = aws_iam_policy.wildcard_policy.arn
}

