"""Tests for fgcheck.model — Evidence, Node, ConfigModel, ParseWarning."""

from __future__ import annotations

from fgcheck.model import ConfigModel, Evidence, Node, ParseWarning


class TestEvidence:
    """Test Evidence dataclass."""

    def test_creation(self):
        e = Evidence(file_id="test.conf", line_range=(1, 5), path=("system", "interface"))
        assert e.file_id == "test.conf"
        assert e.line_range == (1, 5)
        assert e.path == ("system", "interface")
        assert e.raw_lines == []

    def test_frozen(self):
        e = Evidence(file_id="test.conf", line_range=(1, 5), path=("a", "b"))
        try:
            e.file_id = "other.conf"  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except AttributeError:
            pass

    def test_raw_lines_default(self):
        e = Evidence(file_id="x", line_range=(1, 1), path=())
        assert e.raw_lines == []

    def test_raw_lines_custom(self):
        lines = ["set foo bar", "set baz qux"]
        e = Evidence(file_id="x", line_range=(1, 2), path=("a",), raw_lines=lines)
        assert e.raw_lines == lines

    def test_equality(self):
        a = Evidence(file_id="x", line_range=(1, 2), path=("a",))
        b = Evidence(file_id="x", line_range=(1, 2), path=("a",))
        assert a == b

    def test_inequality_different_file(self):
        a = Evidence(file_id="x", line_range=(1, 2), path=("a",))
        b = Evidence(file_id="y", line_range=(1, 2), path=("a",))
        assert a != b

    def test_not_hashable_due_to_list_field(self):
        """Evidence has raw_lines (list) so it can't be used in sets."""
        e = Evidence(file_id="x", line_range=(1, 2), path=("a",))
        try:
            set([e])
            raise AssertionError("Should have raised TypeError for unhashable")
        except TypeError:
            pass


class TestNode:
    """Test Node dataclass."""

    def test_defaults(self):
        n = Node()
        assert n.fields == {}
        assert n.unsets == set()
        assert n.evidence == {}

    def test_mutable(self):
        n = Node()
        n.fields["allowaccess"] = ["ssh", "https"]
        assert n.fields["allowaccess"] == ["ssh", "https"]

    def test_unsets(self):
        n = Node()
        n.unsets.add("allowaccess")
        assert "allowaccess" in n.unsets

    def test_evidence_dict(self):
        n = Node()
        ev = Evidence(file_id="x", line_range=(1, 2), path=("a",))
        n.evidence["set:allowaccess"] = ev
        assert n.evidence["set:allowaccess"] is ev

    def test_effective_fields_empty_unsets(self):
        """effective_fields returns all fields when unsets is empty."""
        n = Node(fields={"a": 1, "b": 2})
        assert n.effective_fields() == {"a": 1, "b": 2}

    def test_effective_fields_with_unsets(self):
        """effective_fields excludes fields that are in unsets."""
        n = Node(fields={"a": 1, "b": 2, "c": 3}, unsets={"b"})
        assert n.effective_fields() == {"a": 1, "c": 3}

    def test_effective_fields_all_unset(self):
        """effective_fields returns empty dict when all fields are unset."""
        n = Node(fields={"a": 1}, unsets={"a"})
        assert n.effective_fields() == {}

    def test_effective_fields_no_overlap(self):
        """effective_fields returns all fields when unsets don't overlap."""
        n = Node(fields={"a": 1}, unsets={"z"})
        assert n.effective_fields() == {"a": 1}

    def test_effective_fields_returns_new_dict(self):
        """effective_fields returns a new dict, not a reference to fields."""
        n = Node(fields={"a": 1}, unsets=set())
        eff = n.effective_fields()
        n.fields["b"] = 2
        assert "b" not in eff

    def test_effective_fields_preserves_type(self):
        """effective_fields preserves value types."""
        n = Node(fields={"str_val": "hello", "list_val": [1, 2], "int_val": 42}, unsets=set())
        eff = n.effective_fields()
        assert eff["str_val"] == "hello"
        assert eff["list_val"] == [1, 2]
        assert eff["int_val"] == 42


class TestConfigModel:
    """Test ConfigModel dataclass."""

    def test_defaults(self):
        m = ConfigModel()
        assert m.meta == {}
        assert m.global_cfg == {}
        assert m.vdoms == {}

    def test_meta_mutable(self):
        m = ConfigModel()
        m.meta["target_fortios"] = "7.6"
        assert m.meta["target_fortios"] == "7.6"

    def test_vdoms_nested(self):
        m = ConfigModel()
        m.vdoms["root"] = {}
        m.vdoms["root"]["system"] = {}
        m.vdoms["root"]["system"]["interface"] = {}
        assert "system" in m.vdoms["root"]

    def test_global_cfg(self):
        m = ConfigModel()
        m.global_cfg["system"] = {"global": Node(fields={"hostname": "fw01"})}
        node = m.global_cfg["system"]["global"]
        assert isinstance(node, Node)
        assert node.fields["hostname"] == "fw01"


class TestParseWarning:
    """Test ParseWarning dataclass."""

    def test_creation(self):
        w = ParseWarning(code="UNKNOWN_KEYWORD", message="Unknown keyword foo", line_no=42)
        assert w.code == "UNKNOWN_KEYWORD"
        assert w.message == "Unknown keyword foo"
        assert w.line_no == 42

    def test_frozen(self):
        w = ParseWarning(code="X", message="Y", line_no=1)
        try:
            w.code = "Z"  # type: ignore[misc]
            raise AssertionError("Should be frozen")
        except AttributeError:
            pass

    def test_equality(self):
        a = ParseWarning(code="X", message="Y", line_no=1)
        b = ParseWarning(code="X", message="Y", line_no=1)
        assert a == b

    def test_hashable(self):
        w = ParseWarning(code="X", message="Y", line_no=1)
        s = {w}
        assert w in s
