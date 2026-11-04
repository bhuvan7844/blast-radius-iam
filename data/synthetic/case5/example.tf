resource "aws_iam_role" "role_a" {
  name = "role-a"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
    "Action": "sts:AssumeRole"
  }]
}
EOF
}

resource "aws_iam_role" "role_b" {
  name = "role-b"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:role/role-a"},
    "Action": "sts:AssumeRole"
  }]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach_a" {
  role       = aws_iam_role.role_a.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "attach_b" {
  role       = aws_iam_role.role_b.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

