"""Tests for fgcheck.util — as_list helper."""
from __future__ import annotations

from fgcheck.util import as_list


class TestAsList:
    """Test as_list utility function."""

    def test_none_returns_empty(self):
        assert as_list(None) == []

    def test_string_returns_singleton(self):
        assert as_list("hello") == ["hello"]

    def test_list_of_strings(self):
        assert as_list(["a", "b", "c"]) == ["a", "b", "c"]

    def test_list_of_ints_converted(self):
        assert as_list([1, 2, 3]) == ["1", "2", "3"]

    def test_int_returns_string_singleton(self):
        assert as_list(42) == ["42"]

    def test_bool_returns_string_singleton(self):
        assert as_list(True) == ["True"]

    def test_float_returns_string_singleton(self):
        assert as_list(3.14) == ["3.14"]

    def test_dict_returns_string_singleton(self):
        assert as_list({"a": 1}) == ["{'a': 1}"]

    def test_empty_list_returns_empty(self):
        assert as_list([]) == []

    def test_mixed_list(self):
        assert as_list(["a", 1, None]) == ["a", "1", "None"]
