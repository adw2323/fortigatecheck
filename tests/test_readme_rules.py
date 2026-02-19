from pathlib import Path
import re


def test_readme_mentions_all_builtin_rule_ids():
    readme = Path("README.md").read_text(encoding="utf-8")
    mentioned = set(re.findall(r"`(FGT-[A-Z0-9-]+)`", readme))
    builtin_ids = {p.stem for p in (Path("rules") / "builtin").glob("FGT-*.yaml")}
    missing = sorted(builtin_ids - mentioned)
    assert not missing, f"README missing rule IDs: {missing}"
