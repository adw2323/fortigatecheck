# Contributing to fortigatecheck

**Tags:** #fortigatecheck #contributing

---

## Welcome!

We welcome contributions to fortigatecheck. Here's how to get started.

## Ways to Contribute

### 1. Report Issues

Found a bug? Open an issue on GitHub with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Config file (sanitized)
- FortiOS version

### 2. Add Security Rules

The most valuable contribution! See the [Developer Guide](fortigatecheck-developer-guide.md) for how to add rules.

### 3. Improve Documentation

Fix typos, add examples, improve explanations.

### 4. Add Tests

Improve test coverage for existing rules.

### 5. Suggest Features

Open an issue with the `enhancement` label.

## Development Workflow

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/fortigatecheck.git
cd fortigatecheck

# Create branch
git checkout -b feature/my-feature

# Make changes
# ...

# Run tests
python -m pytest tests/

# Commit
git commit -m "feat: add my feature"

# Push
git push origin feature/my-feature

# Create PR
```

## Code Standards

- Python 3.10+
- Type hints on all functions
- Docstrings on public functions
- Tests for all new functionality
- Follow existing patterns

## Rule Contributions

We especially need rules for:
- Wireless security
- DNS filter profiles
- Application control
- ICAP profiles
- Certificate management
- HA configuration
- SD-WAN health checks
- Routing protocols
- VLAN configuration
- QoS policies

## Questions?

Open an issue with the `question` label.
