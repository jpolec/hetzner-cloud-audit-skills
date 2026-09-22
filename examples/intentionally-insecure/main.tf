# INTENTIONALLY INSECURE SYNTHETIC EXAMPLE. Never apply this configuration.
resource "hcloud_firewall" "admin" {
  name = "demo-admin"
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = ["100.64.0.0/10"]
  }
}

# The runtime fixture deliberately differs: 0.0.0.0/0 is observed.
