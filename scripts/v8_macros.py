"""Expand V8's X-macro lists (BYTECODE_LIST, ROOT lists, FOR_EACH_INTRINSIC, ...) from source.

Only what those headers need: comments, line continuations, #if/#ifdef/#ifndef/#elif/#else
with a set of defined symbols, function-like #defines, and argument substitution of the
callback parameters.
"""
import re
from pathlib import Path

DEFAULT_DEFINES = {"V8_INTL_SUPPORT"}


def strip_comments(text):
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            out.append(" ")
            i = n if j < 0 else j + 2
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _eval_condition(expr, defines):
    expr = re.sub(r"defined\s*\(\s*(\w+)\s*\)|defined\s+(\w+)",
                  lambda m: "1" if (m.group(1) or m.group(2)) in defines else "0", expr)
    expr = re.sub(r"\b[A-Za-z_]\w*\b", lambda m: "1" if m.group(0) in defines else "0", expr)
    expr = expr.replace("&&", " and ").replace("||", " or ").replace("!", " not ").replace("not =", "!=")
    try:
        return bool(eval(expr, {}, {}))
    except Exception:
        return False


def preprocess(text, defines):
    """Drop the lines of inactive #if branches and join continuation lines."""
    text = strip_comments(text).replace("\\\n", " ")
    out, stack = [], []  # stack of (active, branch_taken)
    for line in text.split("\n"):
        s = line.strip()
        m = re.match(r"#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", s)
        if not m:
            if all(a for a, _ in stack):
                out.append(line)
            continue
        kind, rest = m.group(1), m.group(2).strip()
        parent = all(a for a, _ in stack)
        if kind in ("ifdef", "ifndef", "if"):
            cond = (rest.split()[0] in defines) if kind == "ifdef" else \
                   (rest.split()[0] not in defines) if kind == "ifndef" else _eval_condition(rest, defines)
            stack.append((parent and cond, cond))
        elif kind == "elif":
            active, taken = stack.pop()
            cond = not taken and _eval_condition(rest, defines)
            stack.append((all(a for a, _ in stack) and cond, taken or cond))
        elif kind == "else":
            active, taken = stack.pop()
            stack.append((all(a for a, _ in stack) and not taken, True))
        elif kind == "endif" and stack:
            stack.pop()
    return "\n".join(out)


def split_args(text):
    """Split a macro argument list on top-level commas (strings and nested parens respected)."""
    args, depth, cur, i = [], 0, [], 0
    while i < len(text):
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < len(text) and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            cur.append(text[i:j + 1])
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def invocations(body):
    """Yield (name, args) for each top-level NAME(...) in a macro body."""
    i = 0
    while True:
        m = re.compile(r"\b([A-Za-z_]\w*)\s*\(").search(body, i)
        if not m:
            return
        depth, j = 1, m.end()
        while j < len(body) and depth:
            c = body[j]
            if c in "\"'":
                k = j + 1
                while k < len(body) and body[k] != c:
                    k += 2 if body[k] == "\\" else 1
                j = k
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            j += 1
        yield m.group(1), split_args(body[m.end():j - 1])
        i = j


class Macros:
    """The function-like #defines of a set of V8 headers."""

    def __init__(self, v8_src, headers, defines=None):
        self.defines = DEFAULT_DEFINES if defines is None else set(defines)
        self.macros = {}
        for h in headers:
            text = preprocess((Path(v8_src) / h).read_text(encoding="utf-8", errors="replace"), self.defines)
            for m in re.finditer(r"^\s*#\s*define\s+(\w+)\(([^)]*)\)(.*)$", text, re.M):
                params = [p.strip() for p in m.group(2).split(",") if p.strip()]
                self.macros[m.group(1)] = (params, m.group(3))

    def expand(self, name, args=("@",), leaf="@"):
        """Leaf entries [(callback, args)] of list macro `name` called with callbacks `args`."""
        params, body = self.macros[name]
        bind = dict(zip(params, args))
        out = []
        for callee, cargs in invocations(body):
            callee = bind.get(callee, callee)
            if callee == leaf:
                out.append(cargs)
            elif callee in self.macros:
                out += self.expand(callee, [bind.get(a, a) for a in cargs], leaf)
        return out
