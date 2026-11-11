"""A small Dockerfile instruction parser (private helper, not a probe)."""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEREDOC_RE = re.compile(r"<<-?\s*['\"]?([A-Za-z_]\w*)['\"]?")
_ESCAPE_DIRECTIVE_RE = re.compile(r"^#\s*escape\s*=\s*(\S)\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class Instruction:
    keyword: str  # upper-case, e.g. "RUN"
    args: str  # continuation lines joined with a single space
    line: int  # 1-based line of the keyword
    end_line: int


@dataclass(frozen=True)
class BuildStage:
    index: int
    image: str  # image reference exactly as written after FROM (flags removed)
    name: str | None  # lower-cased `AS` alias
    platform: str | None
    line: int
    instructions: tuple[Instruction, ...]

    def last(self, keyword: str) -> Instruction | None:
        found = [i for i in self.instructions if i.keyword == keyword]
        return found[-1] if found else None


@dataclass(frozen=True)
class Dockerfile:
    path: str
    global_args: tuple[Instruction, ...]  # ARG instructions before the first FROM
    stages: tuple[BuildStage, ...]

    @property
    def instructions(self) -> tuple[Instruction, ...]:
        return self.global_args + tuple(i for s in self.stages for i in s.instructions)


def _instructions(text: str) -> list[Instruction]:
    lines = text.splitlines()
    escape = "\\"
    for line in lines:  # parser directives must precede everything else
        m = _ESCAPE_DIRECTIVE_RE.match(line.strip())
        if m:
            escape = m.group(1)
        if line.strip() and not line.strip().startswith("#"):
            break
    out: list[Instruction] = []
    i, n = 0, len(lines)
    while i < n:
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i
        parts: list[str] = []
        while True:
            piece = lines[i].strip()
            is_comment = piece.startswith("#") and i != start
            continued = piece.endswith(escape) and not is_comment
            if not is_comment and piece:
                parts.append(piece[:-1].rstrip() if continued else piece)
            i += 1
            # comments and blank lines inside a continuation do not end it
            if i >= n or not (continued or ((is_comment or not piece) and parts and i > start + 1)):
                break
        joined = " ".join(parts)
        keyword, _, args = joined.partition(" ")
        if keyword.upper() in {"RUN", "COPY"}:
            for delimiter in _HEREDOC_RE.findall(args):
                while i < n and lines[i].strip() != delimiter:
                    args += "\n" + lines[i]
                    i += 1
                i += 1
        out.append(Instruction(keyword.upper(), args.strip(), start + 1, i))
    return out


def parse_dockerfile(path: str, text: str) -> Dockerfile:
    global_args: list[Instruction] = []
    stages: list[BuildStage] = []
    current: list[Instruction] = []
    header: tuple[str, str | None, str | None, int] | None = None

    def close() -> None:
        if header is not None:
            image, name, platform, line = header
            stages.append(BuildStage(len(stages), image, name, platform, line, tuple(current)))

    for ins in _instructions(text):
        if ins.keyword == "FROM":
            close()
            tokens = ins.args.split()
            flags = [t for t in tokens if t.startswith("--")]
            rest = [t for t in tokens if not t.startswith("--")]
            platform = next(
                (f.split("=", 1)[1] for f in flags if f.startswith("--platform=")), None
            )
            name = rest[2].lower() if len(rest) >= 3 and rest[1].lower() == "as" else None
            header = (rest[0] if rest else "", name, platform, ins.line)
            current = [ins]
        elif header is None:
            global_args.append(ins)
        else:
            current.append(ins)
    close()
    return Dockerfile(path, tuple(global_args), tuple(stages))
