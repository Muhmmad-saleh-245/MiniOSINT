"""Input validation. Everything that reaches the network passes through here first."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_USERNAME = re.compile(r"^[A-Za-z0-9._-]{2,32}$")
# Names that only make sense inside a private network: refuse them so the tool
# cannot be used to probe internal DNS or internal hosts.
_BLOCKED_SUFFIXES = (
    "localhost", "local", "internal", "lan", "home", "corp", "intranet",
    "localdomain", "home.arpa", "private",
)


class ValidationError(ValueError):
    """The user's input is not acceptable. The message is safe to show to the user."""


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_domain(raw: str) -> str:
    """Return a clean lower-case ASCII (punycode) domain, or raise ValidationError."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationError("Enter a domain name, for example example.com")
    s = raw.strip().lower()
    if "://" in s:
        s = urlparse(s).hostname or ""
    else:
        s = s.split("/")[0].split("?")[0].split("#")[0]
        if "@" in s:
            s = s.rsplit("@", 1)[1]
        if s.count(":") == 1:
            s = s.split(":")[0]
    s = s.rstrip(".")
    if not s:
        raise ValidationError("Enter a domain name, for example example.com")
    if _is_ip(s):
        raise ValidationError("That looks like an IP address. Use the IP lookup tab instead.")
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValidationError("That is not a valid domain name.") from None
    if len(s) > 253:
        raise ValidationError("That domain name is too long.")
    labels = s.split(".")
    if len(labels) < 2:
        raise ValidationError("Enter a full domain such as example.com (not just one word).")
    if not all(_LABEL.match(label) for label in labels):
        raise ValidationError("That is not a valid domain name.")
    if labels[-1].isdigit():
        raise ValidationError("That is not a valid domain name.")
    for suffix in _BLOCKED_SUFFIXES:
        if s == suffix or s.endswith("." + suffix):
            raise ValidationError("Private or internal names cannot be looked up.")
    return s


def normalize_ip(raw: str) -> str:
    """Return a public IP address as text, or raise ValidationError."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValidationError("Enter an IP address, for example 8.8.8.8")
    text = raw.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ValidationError("That is not a valid IPv4 or IPv6 address.") from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        raise ValidationError(
            "Private, loopback, link-local and reserved addresses cannot be looked up "
            "(they are not public information)."
        )
    return str(ip)


def normalize_username(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValidationError("Enter a username.")
    s = raw.strip().lstrip("@")
    if not _USERNAME.match(s):
        raise ValidationError(
            "Usernames must be 2-32 characters: letters, digits, dot, underscore or dash."
        )
    return s
