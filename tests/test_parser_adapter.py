import pytest
from core.parser_adapter import BashParserAdapter, ParserCoverage


def test_parse_simple_command():
    tree = BashParserAdapter.parse("ls -la")
    assert tree.coverage == ParserCoverage.FULL
    assert len(tree.commands) == 1
    assert tree.commands[0].verb == "ls"
    assert tree.commands[0].args == ["-la"]
    assert len(tree.commands[0].redirects) == 0


def test_parse_chained_command():
    tree = BashParserAdapter.parse("ls -la && rm -rf build/")
    assert tree.coverage == ParserCoverage.FULL
    assert len(tree.commands) == 2
    assert tree.commands[0].verb == "ls"
    assert tree.commands[1].verb == "rm"
    assert tree.commands[1].args == ["-rf", "build/"]
    assert tree.operators == ["&&"]


def test_parse_pipeline():
    tree = BashParserAdapter.parse("cat server.log | grep ERROR")
    assert tree.coverage == ParserCoverage.FULL
    assert len(tree.commands) == 2
    assert tree.commands[0].verb == "cat"
    assert tree.commands[1].verb == "grep"
    assert tree.operators == ["|"]


def test_parse_redirects():
    tree = BashParserAdapter.parse("echo hello > out.txt")
    assert tree.coverage == ParserCoverage.FULL
    assert len(tree.commands) == 1
    assert tree.commands[0].verb == "echo"
    assert len(tree.commands[0].redirects) == 1
    assert tree.commands[0].redirects[0].op == ">"
    assert tree.commands[0].redirects[0].target == "out.txt"


def test_parse_command_substitution_marked_partial():
    tree = BashParserAdapter.parse("cat $(echo /etc/passwd)")
    assert tree.coverage == ParserCoverage.PARTIAL
    assert tree.commands[0].has_subshell is True
    assert "command_substitution" in tree.unsupported_reasons


def test_parse_syntax_error_unsupported():
    tree = BashParserAdapter.parse("for (( i=0; i<10; i++ ))")
    assert tree.coverage == ParserCoverage.UNSUPPORTED
    assert tree.error_message is not None
