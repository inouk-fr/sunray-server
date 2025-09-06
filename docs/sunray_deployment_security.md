# Sunray Deployment Security Guide

## Overview

This guide covers essential security configurations for protecting your Sunray deployment in production environments.

## Sunray Server Access Control

The Sunray Server must be secured to allow traffic only from trusted sources:
- Whitelisted office IP addresses (for admin access)
- Authenticated Sunray Workers (via API keys)

### Cloudflare WAF Configuration Example

To protect your Sunray Server using Cloudflare WAF, create a custom rule:

```
(
    http.host wildcard "{{sunray_server_url}}" 
    and not (
        ip.src in $my_offices_list  // use a list of whitelisted IPs
        or any(http.request.headers["authorization"][*] eq "Bearer {{worker_api_token}}")
    )
)
```

**Note**: Adjust this rule to include all your worker API tokens when running multiple workers.

### Alternative Firewall Solutions

For non-Cloudflare deployments, implement equivalent rules in your firewall solution:
- **NGINX**: Use `allow` and `deny` directives with IP ranges
- **iptables**: Configure INPUT rules for specific source IPs
- **AWS Security Groups**: Whitelist office IPs and worker origins

## Protected Host Security

Your protected hosts must follow standard Cloudflare exposure rules:
- Traffic should be restricted to Cloudflare Workers IP ranges only
- Direct origin access must be blocked (may be except for whitelisted office IPs)

To protect your 'Protected Host' using Cloudflare WAF, create a custom rule like:

```
( 
    http.host in { "xxx.domain.app" "thing.domain2.net" .... } 
    and not ip.src in {5.x.y.225 k.l.69.75 ...} // or best use a list
)
Action: Block
```
### Automated Configuration with Muppy

With Muppy, you can use Cloudflare CIDR Dynamic Rules to automatically configure this protection, ensuring your origins only accept traffic from legitimate Cloudflare edge servers.

## Security Checklist

- [ ] Sunray Server accessible only from office IPs and workers
- [ ] Worker API keys properly configured in WAF rules
- [ ] Protected hosts restricted to Cloudflare IP ranges
- [ ] Direct origin access blocked for all protected applications
- [ ] Regular review of access logs for unauthorized attempts