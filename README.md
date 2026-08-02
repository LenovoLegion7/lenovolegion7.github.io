# LenovoLegion7 Cybersecurity Write-ups

Source repository for my personal cybersecurity write-up portfolio.

The site documents authorized TryHackMe labs, security exercises, and related technical assessments.

## Website

The public site will be available at:

```text
https://lenovolegion7.github.io
```

## Main Topics

- Web application security
- Active Directory and Windows security
- Linux and Windows privilege escalation
- Network and infrastructure security
- Digital forensics and incident response
- AI security and prompt injection
- Technical security reporting

## Local Development

Install the required Ruby dependencies:

```bash
bundle install
```

Start the local Jekyll development server:

```bash
bundle exec jekyll serve \
  --host 0.0.0.0 \
  --port 4000 \
  --livereload
```

Open the forwarded port `4000` in the browser.

## Content Policy

All reports document authorized training environments. Sensitive information such as flags, credentials, hashes, tokens, cookies, private keys, and personal infrastructure details may be redacted.

## Theme

This site uses the Jekyll Theme Chirpy.

License information is available in the repository's `LICENSE` file.