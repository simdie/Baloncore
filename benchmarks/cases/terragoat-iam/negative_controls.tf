# BALONCORE negative controls for the TerraGoat cloud benchmark.
#
# These are NOT part of TerraGoat. They are correctly-configured resources that
# bench-terragoat feeds to analyze-cloud-iam ALONGSIDE the vendored TerraGoat
# .tf files. They are the cloud false-positive guard: a credible analyzer must
# NOT flag any of these. If analyze-cloud-iam reports a finding on one of these,
# the bench scores it as a decoy false positive (the FP that kills credibility
# with security buyers).

# Least-privilege inline policy: a single scoped action on a specific resource,
# no wildcards. The over-privileged check must NOT fire on this.
resource "aws_iam_user" "app" {
  name = "baloncore-decoy-app-user"
}

resource "aws_iam_user_policy" "scoped" {
  name = "baloncore-decoy-scoped-policy"
  user = aws_iam_user.app.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": ["s3:GetObject"],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::baloncore-decoy-bucket/reports/*"
    }
  ]
}
EOF
}

# Security group restricted to an internal CIDR — no 0.0.0.0/0. The
# public-exposure check must NOT fire on this.
resource "aws_security_group" "internal" {
  name        = "baloncore-decoy-internal-sg"
  description = "internal-only access"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
