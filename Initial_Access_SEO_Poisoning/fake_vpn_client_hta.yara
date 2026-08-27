rule fake_vpn_client_hta
{
  meta:
    author = "WithSecure"
    description = "Detects HTA files masqeurading as fake VPN clients"
    target_entity = "file"
  strings:
    $a = "yes-hta-2025"
    $b = "X-From-HTA"
  condition:
    any of them
}
