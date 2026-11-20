"""
Bash parser adapter for Checkpoint — Phase 0 / Feature 4 / Feature 5.

Uses bashlex behind an explicit adapter interface with support matrix.
Licence notice: bashlex is licensed under GPL-3.0-or-later.
In accordance with Checkpoint v2.3 specification Section 4 and Decision Register 2:
- bashlex is approved for private/local research development in this project.
- The GPL-3.0-or-later notice is preserved.
- Do not distribute Checkpoint with bashlex bundled or linked without prior legal review.

This adapter isolates the rest of Checkpoint from bashlex AST internals
and classifies command constructs according to parser coverage:
- "full": command structure completely understood (AST parts, words, operators, redirects).
- "partial": command parsed with caveats or unresolvable expansions.
- "unsupported": syntax that bashlex fails to parse or constructs outside Git Bash subset.
- "unknown": syntax that cannot be analyzed or dynamic execution.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional, Sequence, Tuple
import bashlex
from bashlex import ast, errors


class ParserCoverage(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


@dataclass
class ParsedRedirect:
    op: str           # '>', '>>', '<', '2>', '&>', etc.
    target: str       # destination path or descriptor
    heredoc: bool = False


@dataclass
class ParsedSimpleCommand:
    words: List[str]                  # words / tokens as string literals
    redirects: List[ParsedRedirect] = field(default_factory=list)
    has_subshell: bool = False
    has_parameter_expansion: bool = False
    has_arithmetic_expansion: bool = False
    has_process_substitution: bool = False
    unsupported_constructs: List[str] = field(default_factory=list)

    @property
    def verb(self) -> str:
        return self.words[0] if self.words else ""

    @property
    def args(self) -> List[str]:
        return self.words[1:] if len(self.words) > 1 else []


@dataclass
class ParsedCommandTree:
    raw_command: str
    commands: List[ParsedSimpleCommand] = field(default_factory=list)
    operators: List[str] = field(default_factory=list)  # '&&', '||', ';', '|'
    coverage: ParserCoverage = ParserCoverage.FULL
    error_message: Optional[str] = None
    unsupported_reasons: List[str] = field(default_factory=list)


class BashParserAdapter:
    """
    Adapter wrapping bashlex with safe error handling and capability detection.
    """

    SUPPORTED_OPERATORS = frozenset(["&&", "||", ";", "|", "&"])

    @classmethod
    def parse(cls, command: str) -> ParsedCommandTree:
        cmd = command.strip()
        if not cmd:
            return ParsedCommandTree(raw_command=command, coverage=ParserCoverage.FULL)

        try:
            parts = bashlex.parse(cmd)
        except errors.ParsingError as e:
            return ParsedCommandTree(
                raw_command=cmd,
                coverage=ParserCoverage.UNSUPPORTED,
                error_message=f"bashlex syntax parsing error: {e}",
                unsupported_reasons=["syntax_parsing_error"]
            )
        except Exception as e:
            return ParsedCommandTree(
                raw_command=cmd,
                coverage=ParserCoverage.UNKNOWN,
                error_message=f"Unexpected parser failure: {e}",
                unsupported_reasons=["parser_crash"]
            )

        tree = ParsedCommandTree(raw_command=cmd)
        for part in parts:
            cls._visit_node(part, tree)

        if tree.unsupported_reasons:
            if any(r in ("parser_crash", "syntax_parsing_error") for r in tree.unsupported_reasons):
                tree.coverage = ParserCoverage.UNSUPPORTED
            else:
                tree.coverage = ParserCoverage.PARTIAL

        return tree

    @classmethod
    def _visit_node(cls, node: Any, tree: ParsedCommandTree):
        kind = getattr(node, "kind", None)

        if kind == "list":
            for part in node.parts:
                cls._visit_node(part, tree)

        elif kind == "operator":
            op = getattr(node, "op", "")
            tree.operators.append(op)
            if op not in cls.SUPPORTED_OPERATORS:
                tree.unsupported_reasons.append(f"unsupported_operator_{op}")

        elif kind == "pipeline":
            for part in node.parts:
                cls._visit_node(part, tree)

        elif kind == "pipe":
            op = getattr(node, "pipe", "|")
            tree.operators.append(op)

        elif kind == "command":
            simple = cls._parse_simple_command(node)
            tree.commands.append(simple)
            if simple.unsupported_constructs:
                tree.unsupported_reasons.extend(simple.unsupported_constructs)

        elif kind == "compound":
            tree.unsupported_reasons.append("compound_command")
            for sub in getattr(node, "list", []):
                cls._visit_node(sub, tree)

        elif kind == "function":
            tree.unsupported_reasons.append("shell_function_definition")

        elif kind == "for" or kind == "while" or kind == "if":
            tree.unsupported_reasons.append(f"control_flow_{kind}")

        else:
            tree.unsupported_reasons.append(f"unrecognized_node_{kind}")

    @classmethod
    def _parse_simple_command(cls, node: Any) -> ParsedSimpleCommand:
        words: List[str] = []
        redirects: List[ParsedRedirect] = []
        unsupported: List[str] = []
        has_subshell = False
        has_param = False
        has_arith = False
        has_proc = False

        for part in getattr(node, "parts", []):
            part_kind = getattr(part, "kind", None)

            if part_kind == "word":
                word_val = getattr(part, "word", "")
                words.append(word_val)
                # Check for expansions embedded inside word parts
                for subpart in getattr(part, "parts", []):
                    sub_kind = getattr(subpart, "kind", None)
                    if sub_kind == "commandsubstitution":
                        has_subshell = True
                        unsupported.append("command_substitution")
                    elif sub_kind == "parameter":
                        has_param = True
                    elif sub_kind == "tilde":
                        pass
                    else:
                        unsupported.append(f"word_expansion_{sub_kind}")

            elif part_kind == "redirect":
                r_type = getattr(part, "type", ">")
                output_node = getattr(part, "output", None)
                target = getattr(output_node, "word", "") if output_node else ""
                heredoc = getattr(part, "heredoc", None) is not None
                redirects.append(ParsedRedirect(op=r_type, target=target, heredoc=heredoc))
                if heredoc:
                    unsupported.append("heredoc_redirect")

            elif part_kind == "assignment":
                pass  # variable assignment prefix, e.g. FOO=1 cmd

            elif part_kind == "commandsubstitution":
                has_subshell = True
                unsupported.append("command_substitution")

            else:
                unsupported.append(f"command_part_{part_kind}")

        return ParsedSimpleCommand(
            words=words,
            redirects=redirects,
            has_subshell=has_subshell,
            has_parameter_expansion=has_param,
            has_arithmetic_expansion=has_arith,
            has_process_substitution=has_proc,
            unsupported_constructs=unsupported,
        )
