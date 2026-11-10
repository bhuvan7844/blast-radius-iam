# example.tf
# ─────────────────────────────────────────────────────────────
# Scenario: 3-tier AWS IAM setup with a live privesc attack path
#
# alice (developer) -> dev-role (open trust) -> admin-role -> crown jewels
# isolated-scanner-role has Action:* but NO trust policy (unreachable)
# ─────────────────────────────────────────────────────────────

# ── Resources (crown jewels) ──────────────────────────────────

resource "aws_s3_bucket" "prod_data_bucket" {
  bucket = "prod-data-bucket"
}

resource "aws_db_instance" "prod_rds_db" {
  identifier = "prod-rds-db"
}

resource "aws_secretsmanager_secret" "secrets_vault" {
  name = "secrets-vault"
}

# ── IAM Users ────────────────────────────────────────────────

resource "aws_iam_user" "alice" {
  name = "alice"
}

# ── IAM Policies ─────────────────────────────────────────────

# alice's policy: PassRole + lambda:CreateFunction (privesc primitive)
resource "aws_iam_policy" "alice_policy" {
  name = "alice-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole", "lambda:CreateFunction", "sts:AssumeRole"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "alice_attach" {
  user       = aws_iam_user.alice.name
  policy_arn = aws_iam_policy.alice_policy.arn
}

# dev-role policy: s3:* on prod bucket + iam:AttachRolePolicy (escalation)
resource "aws_iam_policy" "dev_role_policy" {
  name = "dev-role-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "arn:aws:s3:::prod-data-bucket"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:AttachRolePolicy"]
        Resource = "*"
      }
    ]
  })
}

# ── IAM Roles ─────────────────────────────────────────────────

# dev-role: open trust (Principal=*) — anyone can assume it
resource "aws_iam_role" "dev_role" {
  name = "dev-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "dev_role_attach" {
  role       = aws_iam_role.dev_role.name
  policy_arn = aws_iam_policy.dev_role_policy.arn
}

# admin-role: full admin, assumable only by dev-role
resource "aws_iam_role" "admin_role" {
  name = "admin-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.dev_role.arn
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "admin_role_policy" {
  role = aws_iam_role.admin_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# isolated-scanner-role: full admin BUT no trust policy (nobody can assume it)
# A plain scanner flags this HIGH. Blast-radius knows it is unreachable.
resource "aws_iam_role" "isolated_scanner_role" {
  name = "isolated-scanner-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = []
  })
}

resource "aws_iam_role_policy" "isolated_scanner_role_policy" {
  role = aws_iam_role.isolated_scanner_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
