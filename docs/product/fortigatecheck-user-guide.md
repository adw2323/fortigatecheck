# fortigatecheck User Guide

**Version:** 0.1.0
**Last Updated:** 2026-07-03

---

## Installation

```bash
# From source
git clone https://github.com/adw2323/fortigatecheck.git
cd fortigatecheck
pip install -e .

# Or directly
pip install git+https://github.com/adw2323/fortigatecheck.git
```

## Quick Start

### Scan a single config

```bash
fgcheck config.conf
```

### Scan multiple configs

```bash
fgcheck configs/
```

### JSON output

```bash
fgcheck config.conf --format json
```

### HTML report

```bash
fgcheck configs/ --format html --output report.html
```

## CLI Reference

### Scan Command (default)

```bash
fgcheck <path> [options]

Options:
  --format FORMAT    Output format: human, json, md, html, pdf
  --output FILE      Write output to file
  --fortios VERSION  Target FortiOS version (default: 7.6)
  --rules FILE       Custom rule file(s)
  --no-color         Disable colored output
  --quiet            Suppress stdout output
  --fail-on SEVERITY Exit non-zero if findings at this severity or higher
  --summary-output FILE  Write summary JSON
```

### Authority Command

```bash
fgcheck authority <query> [options]

Options:
  --fortios VERSION  Target FortiOS version
  --format FORMAT    Output format: human, json
  --strict           Exit non-zero unless fully validated
```

### Schema Command

```bash
fgcheck schema <query> [options]

Options:
  --fortios VERSION  Target FortiOS version
  --format FORMAT    Output format: human, json
  --strict           Exit non-zero unless fully validated
```

## Output Formats

### Human (default)

```
FGT-ADMIN-EDGE-SSH [CRITICAL]
Interface "wan1" is edge (via default route) and allows SSH management.
Evidence: set allowaccess ssh
```

### JSON

```json
{
  "findings": [
    {
      "rule_id": "FGT-ADMIN-EDGE-SSH",
      "title": "Edge interface exposes SSH management",
      "severity": "critical",
      "confidence": "certain",
      "vdom": "root",
      "message": "Interface \"wan1\" is edge...",
      "evidence": [...]
    }
  ]
}
```

### HTML

Generates a styled HTML report with:
- Summary statistics
- Findings grouped by severity
- Evidence details
- Rule explanations

### PDF

Generated from HTML using weasyprint:
```bash
pip install weasyprint
fgcheck configs/ --format html --output report.html --pdf-output report.pdf
```

## Examples

### Basic scan

```bash
fgcheck /path/to/fortigate-config.conf
```

### Scan with specific version

```bash
fgcheck config.conf --fortios 7.6.6
```

### Scan and fail on critical findings

```bash
fgcheck configs/ --fail-on critical
```

### Generate compliance report

```bash
fgcheck configs/ --format html --output compliance-report.html --report-title "Q4 Security Audit"
```

### Check if a command is valid

```bash
fgcheck authority "firewall policy set action accept"
```

## Troubleshooting

### "No findings" — is the config valid?

The parser may not have recognized the config format. Ensure:
- Config is from `show config full` output
- File encoding is UTF-8 or ASCII
- File is not truncated

### Slow performance on large configs

For configs >5MB:
- Use `--quiet` to suppress output
- Consider splitting by VDOM
- Check if config has circular references

### Schema warnings

"schema_unknown" warnings mean the schema doesn't cover that table/field. This is normal for partial schemas. The check still works using heuristic confidence.
