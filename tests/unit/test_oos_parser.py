"""Tests for intelligent exclusions parser."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.oos_parser import IntelligentExclusionsParser, parse_exclusions_text


class TestIntelligentExclusionsParser:
    def test_comma_separated_domains(self):
        oos, parsed = parse_exclusions_text("admin.example.com, *.internal.io")
        assert "admin.example.com" in oos
        assert "*.internal.io" in oos or any("internal" in x for x in oos)

    def test_multiline_policy(self):
        text = """
        Out of scope:
        staging.example.com
        /admin/
        Do not test denial of service
        """
        oos, parsed = parse_exclusions_text(text, in_scope=["example.com"])
        assert "staging.example.com" in oos or any("staging" in x for x in oos)
        assert "dos" in parsed.excluded_vuln_types

    def test_vuln_type_exclusion_match(self):
        assert IntelligentExclusionsParser.is_vuln_type_excluded(
            "Denial of Service", "Possible DoS", ["dos"]
        )

    def test_empty_text(self):
        oos, parsed = parse_exclusions_text("")
        assert oos == []
        assert parsed.domains == []
