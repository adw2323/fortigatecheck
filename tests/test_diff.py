"""Tests for config diff utility."""

from __future__ import annotations

from fgcheck.diff import diff_configs, diff_configs_from_text
from fgcheck.model import ConfigModel, Node


class TestDiffConfigs:
    def test_no_changes(self):
        model1 = ConfigModel()
        model1.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "accept"})}}
        model2 = ConfigModel()
        model2.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "accept"})}}
        diff = diff_configs(model1, model2)
        assert len(diff.changes) == 0

    def test_field_changed(self):
        model1 = ConfigModel()
        model1.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "accept"})}}
        model2 = ConfigModel()
        model2.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "deny"})}}
        diff = diff_configs(model1, model2)
        assert len(diff.changes) == 1
        assert diff.changes[0].change_type == "changed"
        assert diff.changes[0].old_value == "accept"
        assert diff.changes[0].new_value == "deny"
        assert diff.changes[0].severity == "high"

    def test_entry_added(self):
        model1 = ConfigModel()
        model1.vdoms["root"] = {}
        model2 = ConfigModel()
        model2.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "accept"})}}
        diff = diff_configs(model1, model2)
        assert len(diff.changes) == 1
        assert diff.changes[0].change_type == "added"

    def test_entry_removed(self):
        model1 = ConfigModel()
        model1.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "accept"})}}
        model2 = ConfigModel()
        model2.vdoms["root"] = {}
        diff = diff_configs(model1, model2)
        assert len(diff.changes) == 1
        assert diff.changes[0].change_type == "removed"

    def test_security_field_change(self):
        model1 = ConfigModel()
        model1.vdoms["root"] = {"system interface": {"edit wan1": Node(fields={"allowaccess": "ssh"})}}
        model2 = ConfigModel()
        model2.vdoms["root"] = {
            "system interface": {"edit wan1": Node(fields={"allowaccess": "ssh https http telnet"})}
        }
        diff = diff_configs(model1, model2)
        assert len(diff.changes) == 1
        assert diff.changes[0].severity == "high"

    def test_summary(self):
        model1 = ConfigModel()
        model1.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "accept"})}}
        model2 = ConfigModel()
        model2.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "deny"})}}
        diff = diff_configs(model1, model2)
        assert "high" in diff.summary
        assert diff.summary["high"] == 1

    def test_to_dict(self):
        model1 = ConfigModel()
        model1.vdoms["root"] = {}
        model2 = ConfigModel()
        model2.vdoms["root"] = {"firewall policy": {"edit 1": Node(fields={"action": "accept"})}}
        diff = diff_configs(model1, model2)
        d = diff.to_dict()
        assert "changes" in d
        assert "summary" in d
        assert "total_changes" in d
        assert d["total_changes"] == 1


class TestDiffFromText:
    def test_diff_texts(self):
        old = "config firewall policy\n    edit 1\n        set action accept\n    next\nend\n"
        new = "config firewall policy\n    edit 1\n        set action deny\n    next\nend\n"
        diff = diff_configs_from_text(old, new)
        assert len(diff.changes) >= 1

    def test_identical_texts(self):
        config = "config firewall policy\n    edit 1\n        set action accept\n    next\nend\n"
        diff = diff_configs_from_text(config, config)
        assert len(diff.changes) == 0
