resource "aws_s3_bucket" "bucket1" {
  bucket = "my-bucket"
}

resource "aws_iam_role" "dev_role" {
  name = "dev-role"
  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "sts:AssumeRole"
      }
    ]
  }
EOF
}

resource "aws_iam_role_policy" "dev_policy" {
  role   = aws_iam_role.dev_role.name
  policy = <<POLICY
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:*"],
        "Resource": "*"
      }
    ]
  }
POLICY
}

