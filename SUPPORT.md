# Support

## Getting Help with QACyberWatch

### Documentation
- [README](README.md) — Setup, features, and usage guide
- [CONTRIBUTING](CONTRIBUTING.md) — Development setup and guidelines
- [CHANGELOG](CHANGELOG.md) — Version history

### Community Support

- **GitHub Issues**: [Open an issue](https://github.com/SiteQ8/QACyberWatch/issues) for bug reports and feature requests
- **GitHub Discussions**: Ask questions and share ideas
- **Email**: Site@hotmail.com

### Reporting Security Issues

**Do not** use GitHub Issues for security vulnerabilities. Please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

### Priority Support

For organizations in Qatar's financial or government sectors requiring priority support for phishing detection and brand protection, contact:

**Ali AlEnezi**
- Email: Site@hotmail.com
- GitHub: [@SiteQ8](https://github.com/SiteQ8)

### FAQ

**Q: Can I add my own brand keywords for monitoring?**
A: Yes — edit `config.yaml` to add custom keywords and protected brand domains.

**Q: Does this work with commercial SIEM platforms?**
A: Yes — use the webhook notification system to forward alerts to Splunk, QRadar, Sentinel, or any SIEM with webhook ingestion.

**Q: Is there an API rate limit?**
A: The default rate limit is 100 requests/hour. Configurable in `config.yaml`.

**Q: Can I run this in an air-gapped environment?**
A: The core detection engine works offline. CertStream monitoring and threat intelligence integrations require internet access.
