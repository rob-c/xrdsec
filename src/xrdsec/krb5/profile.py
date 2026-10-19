"""``krb5.conf``: where the KDCs are, and which realm a host belongs to.

The file is MIT's "profile" format - ``[sections]`` of ``tag = value``
relations, where a value can itself be a ``{ ... }`` block - and a tag may
repeat (``kdc`` usually does). ``include FILE`` and ``includedir DIR`` are
followed, because RHEL and its relatives keep much of their configuration
in ``/etc/krb5.conf.d/``. ``$KRB5_CONFIG`` is a colon-separated list of
files, read in order, and replaces ``/etc/krb5.conf`` when set, as in MIT.

Only what an AP-REQ login needs is interpreted: ``default_realm``,
``default_ccache_name``, the enctype lists, ``udp_preference_limit``,
``[realms] REALM = { kdc = ... }`` and ``[domain_realm]``. DNS is never
consulted - no SRV lookup for KDCs, no TXT lookup for realms, and no host
name canonicalisation - which is what MIT does with ``dns_lookup_kdc``,
``dns_lookup_realm`` and ``dns_canonicalize_hostname`` all false. The
server names its own principal in its offer, so canonicalisation is not
needed to find it; a KDC must be listed in the file.

Parsing is forgiving where MIT is strict: a malformed line is skipped, an
unreadable include is logged at debug and skipped, and a missing file is
an empty profile. A login that then fails names the setting it lacked
(see :func:`.kdc.exchange`), which is a better message than "syntax error
in krb5.conf line 40" for a file the user did not write and cannot fix.
"""

from __future__ import annotations

import os
import re
from typing import Union

from xrdcore.log import get_logger

__all__ = ["DEFAULT_CONFIG", "Profile", "enctype_list"]

_log = get_logger(__name__)

#: MIT's compiled-in profile path, used when ``$KRB5_CONFIG`` is unset.
DEFAULT_CONFIG = "/etc/krb5.conf"

#: A relation's value: a string, or a block of further relations.
Value = Union[str, "Block"]
Block = dict[str, list[Value]]

#: The whole file: ``[section]`` name to its block of relations.
Sections = dict[str, Block]

#: MIT's rule for which files ``includedir`` reads.
_INCLUDEDIR_NAME = re.compile(r"^(?:[A-Za-z0-9_-]+|.*\.conf)$")

#: A directive: its word at the very start of the line, then white space.
_DIRECTIVE = re.compile(r"(include|includedir|module)\s(.*)", re.DOTALL)

#: Boolean spellings MIT's ``profile_parse_boolean`` accepts as true;
#: anything else that is set reads as false.
_TRUE = ("y", "yes", "true", "t", "1", "on")

#: Enctype names ``krb5.conf`` may use, to their numbers. Names this client
#: does not implement are simply not here, so they drop out of a list.
_ENCTYPE_NAMES = {
    "aes128-cts-hmac-sha1-96": (17,),
    "aes128-cts": (17,),
    "aes128-sha1": (17,),
    "aes256-cts-hmac-sha1-96": (18,),
    "aes256-cts": (18,),
    "aes256-sha1": (18,),
    "aes128-cts-hmac-sha256-128": (19,),
    "aes128-sha2": (19,),
    "aes256-cts-hmac-sha384-192": (20,),
    "aes256-sha2": (20,),
    "aes": (18, 17, 20, 19),
    "aes-sha1": (18, 17),
    "aes-sha2": (20, 19),
}


class _Parser:
    """One file's worth of relations, merged into a shared tree.

    ``stack`` is the path of open blocks: its bottom is the current
    section's block, and each ``tag = {`` pushes a nested one. ``seen``
    holds the real paths already read, shared across includes, so an
    include loop (a file that includes its own directory) terminates.
    """

    def __init__(self, tree: Sections, seen: set[str]) -> None:
        """Parse into ``tree``, skipping any real path already in ``seen``."""
        self.tree = tree
        self.seen = seen
        self.stack: list[Block] = []

    def feed(self, text: str, origin: str) -> None:
        """Parse ``text`` line by line; ``origin`` names it in debug logs.

        Comments are whole lines starting ``#`` or ``;`` - MIT has no
        trailing comments, so a ``#`` inside a value is part of it.
        Directives are matched on the raw line because MIT only honours one
        that starts in column 0.
        """
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            if self._directive(raw, origin):
                continue
            self._line(line)

    def _directive(self, raw: str, origin: str) -> bool:
        """``include``, ``includedir`` and ``module``, which MIT reads first on a line.

        As in MIT's ``prof_parse.c``: a directive starts the line, its word
        is followed by any white space, and ``include`` and ``includedir``
        count anywhere in the file - after a ``[section]``, even inside a
        block - while ``module`` only counts before the first section.
        """
        found = _DIRECTIVE.match(raw)
        if found is None:
            return False
        word, rest = found[1], found[2].strip()
        if word == "include":
            self.read(rest)
        elif word == "includedir":
            self._read_dir(rest)
        elif self.stack:
            return False  # ``module`` inside a section is just a line
        else:
            _log.debug("%s: ignoring profile module %s", origin, rest)
        return True

    def _line(self, line: str) -> None:
        """One stripped, non-comment line: a section header, a ``}``, or a relation."""
        if line.startswith("["):
            name = line[1:].split("]", 1)[0].strip()
            # A section named twice - in two files, say - is one section.
            self.stack = [self.tree.setdefault(name, {})]
            return
        if line.startswith("}"):
            # Never pop the section itself: a stray "}" is noise, not an
            # instruction to start writing outside every section.
            if len(self.stack) > 1:
                self.stack.pop()
            return
        if not self.stack or "=" not in line:
            return  # a relation outside any section, or noise: MIT would refuse the file
        tag, _, value = (part.strip() for part in line.partition("="))
        tag = tag.rstrip("*").rstrip()  # a "final" marker changes nothing for a reader
        if value.startswith("{"):
            block: Block = {}
            self.stack[-1].setdefault(tag, []).append(block)
            self.stack.append(block)
            return
        self.stack[-1].setdefault(tag, []).append(_unquote(value))

    def read(self, path: str) -> None:
        """Merge the file at ``path`` into the tree, once per real path.

        Undecodable bytes are replaced: a stray Latin-1 comment must not
        cost the KDC list on the next line.
        """
        real = os.path.realpath(path)
        if real in self.seen:
            return
        self.seen.add(real)
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError as exc:
            _log.debug("krb5 profile %s unreadable: %s", path, exc)
            return
        # An included file starts outside any section, as it does in MIT.
        saved, self.stack = self.stack, []
        self.feed(text, path)
        self.stack = saved

    def _read_dir(self, path: str) -> None:
        """``includedir``: the matching files in ``path``, in sorted order.

        Sorted so that the merge order - and so which ``default_realm`` is
        "first" - does not depend on directory order on disk. Editor backups
        and ``.rpmsave`` files fail :data:`_INCLUDEDIR_NAME` and are skipped.
        """
        try:
            names = sorted(os.listdir(path))
        except OSError as exc:
            _log.debug("krb5 includedir %s unreadable: %s", path, exc)
            return
        for name in names:
            if _INCLUDEDIR_NAME.match(name):
                self.read(os.path.join(path, name))


def _unquote(value: str) -> str:
    """A relation's value, with double quotes and their escapes undone.

    Only fully quoted values are unescaped, and only ``\\n``, ``\\t`` and
    ``\\b`` mean anything special; any other escaped character stands for
    itself, as in ``prof_parse.c``.
    """
    if len(value) >= 2 and value[0] == value[-1] == '"':
        inner = value[1:-1]
        return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "b": "\b"}.get(m[1], m[1]), inner)
    return value


def enctype_list(text: str) -> list[int]:
    """An enctype list from ``krb5.conf``, as numbers this client can use.

    Names are separated by spaces or commas; ``-name`` removes; ``DEFAULT``
    is this client's own order. Unknown names are ignored, as MIT ignores
    names it has no implementation of.
    """
    from .rfc3961 import SUPPORTED_ENCTYPES

    out: list[int] = []
    for word in re.split(r"[\s,]+", text.strip()):
        remove = word.startswith("-")
        name = word.lstrip("+-").lower()
        numbers = SUPPORTED_ENCTYPES if name == "default" else _ENCTYPE_NAMES.get(name, ())
        for number in numbers:
            if number in out:
                out.remove(number)
            if not remove:
                out.append(number)
    return out


class Profile:
    """The merged configuration: look values up by section and tag path.

    Immutable in use: built once by :meth:`load` or :meth:`parse` and then
    only read, so one instance can be shared between threads. Lookups never
    raise; an absent section or tag is an empty list or the default.
    """

    __slots__ = ("tree",)

    def __init__(self, tree: Sections | None = None) -> None:
        """Wrap an already-parsed tree; no tree is the empty configuration."""
        self.tree: Sections = tree if tree is not None else {}

    @classmethod
    def parse(cls, text: str) -> Profile:
        """A profile from a string, as if it were one file (includes are followed)."""
        parser = _Parser({}, set())
        parser.feed(text, "<string>")
        return cls(parser.tree)

    @classmethod
    def load(cls, paths: str | None = None) -> Profile:
        """``$KRB5_CONFIG`` (colon-separated), else ``/etc/krb5.conf``.

        Missing files are skipped, as MIT skips them.
        """
        spec = paths if paths is not None else os.environ.get("KRB5_CONFIG") or DEFAULT_CONFIG
        parser = _Parser({}, set())
        for path in spec.split(":"):
            if path:
                parser.read(path)
        return cls(parser.tree)

    def values(self, section: str, *path: str) -> list[str]:
        """Every string value at ``[section] path...``, in file order."""
        blocks: list[Value] = [self.tree[section]] if section in self.tree else []
        for tag in path:
            blocks = [
                value for block in blocks if isinstance(block, dict) for value in block.get(tag, [])
            ]
        return [value for value in blocks if isinstance(value, str)]

    def first(self, section: str, *path: str, default: str = "") -> str:
        """The first value at a path - the one MIT uses for a single-valued tag."""
        found = self.values(section, *path)
        return found[0] if found else default

    def libdefault(self, tag: str, default: str = "") -> str:
        """A ``[libdefaults]`` setting, as a string; ``default`` when unset."""
        return self.first("libdefaults", tag, default=default)

    def flag(self, tag: str, default: bool) -> bool:
        """A boolean ``[libdefaults]`` setting, spelled any way MIT accepts."""
        value = self.libdefault(tag)
        return value.lower() in _TRUE if value else default

    @property
    def default_realm(self) -> str:
        """``default_realm``, or ``""`` - which leaves a bare principal realmless."""
        return self.libdefault("default_realm")

    def kdcs(self, realm: str) -> list[str]:
        """The ``kdc`` entries for ``realm``: ``host``, ``host:port``, ``tcp/host`` and so on.

        Every repetition of ``kdc`` counts, in file order, and one value may
        hold several space-separated entries, as MIT allows.
        """
        return [entry for value in self.values("realms", realm, "kdc") for entry in value.split()]

    def realm_for_host(self, host: str) -> str:
        """``[domain_realm]``: an exact host entry, else the longest ``.domain`` suffix.

        Returns ``""`` when nothing maps, which callers read as "the client's
        own realm" - where a KDC referral would send MIT anyway.
        """
        host = host.lower().rstrip(".")
        labels = host.split(".")
        # MIT's order: the host itself, then ".rest.of.name" one label at a time.
        candidates = [host] + ["." + ".".join(labels[i:]) for i in range(1, len(labels))]
        for name in candidates:
            found = self.first("domain_realm", name)
            if found:
                return found
        return ""
