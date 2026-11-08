# Security notes

PhishGuard is a defensive, static website-analysis project.

## Safe operation
- Run the live scanner on a trusted machine and keep it bound to localhost.
- Do not expose the live URL-fetching API directly to the public internet.
- Use deep scanning only on systems you own or are explicitly authorized to assess.
- Keep dependencies updated and protect the SQLite database and admin key.
- Treat community reports as untrusted signals until corroborated.

## URL fetching
The fetcher limits protocols, ports, redirects, response size and timeouts, and
rejects destinations that resolve to non-public IP addresses. The project
README describes the remaining DNS-rebinding limitation. For production, place
outbound scanning behind an egress firewall or policy-enforcing proxy that
blocks private, loopback, link-local and metadata destinations. A URL scanner
should never have unrestricted access to internal networks.

## Reporting
Never submit personal information, passwords, session cookies, or confidential
material in community report comments. A scan is decision support, not a
guarantee. Verify important findings independently.
