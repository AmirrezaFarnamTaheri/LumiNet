# Post-refactor-234 security model

No new planner fetches blocklists/resolver lists, captures traffic, installs MITM certificates, controls Tor, installs kernel/network-extension filters, starts dnscrypt-proxy, changes system DNS, or imports provider account/session authority. Unknown cryptographic evidence is never treated as pass; process-proxy self-routing is surfaced as a loop risk; Tor flags remain descriptive rather than trust authority.
