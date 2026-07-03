# fortigatecheck Getting Started

**Tags:** #fortigatecheck #quickstart

---

## Prerequisites

- Python 3.10+
- pip

## Step 1: Install

```bash
cd /c/git/fortigatecheck
pip install -e .
```

## Step 2: Get a FortiGate Config

```bash
# On FortiGate
execute backup full-config config.conf
# Or
show config full
```

## Step 3: Run Your First Scan

```bash
fgcheck config.conf
```

You'll see findings like:

```
FGT-ADMIN-EDGE-SSH [CRITICAL]
Interface "wan1" is edge and allows SSH management.
Evidence: set allowaccess ssh
```

## Step 4: Generate a Report

```bash
fgcheck config.conf --format html --output my-report.html
```

Open `my-report.html` in a browser to see a styled report.

## Step 5: Batch Scan

```bash
fgcheck configs/ --format json --output results.json
```

This scans all configs in the `configs/` directory and writes JSON results.

## Next Steps

- Read the [User Guide](fortigatecheck-user-guide.md)
- Check the [Rules Catalog](fortigatecheck-rules-catalog.md)
- Look at the [Roadmap](ROADMAP.md)
- Contribute a new rule!
