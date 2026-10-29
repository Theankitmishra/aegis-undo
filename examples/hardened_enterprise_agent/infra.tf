resource "aws_security_group" "agent_sg" {
  name = "hardened-agent-sg"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.24.0.0/16"]
  }
}

data "aws_iam_policy_document" "agent_role" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::corp-approved-kb/*"]
  }
}
