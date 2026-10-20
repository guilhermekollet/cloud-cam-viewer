"""Guards for the values that decide where credentials and media go.

The cloud tells the client which host to use next: the login answers with a
regional `apiDomain`, the token file stores it, and the resource list names the
VTM relay. None of that was checked, so whatever host a response named received
the account password (MD5, replayable), the session id, or a raw TCP connection
from inside the deployment network.

`check_api_domain` restricts API hosts to the vendors' own domains.
`check_media_host` keeps the relay connection off private and loopback
addresses. `write_private` writes secrets atomically and readable only by the
owner — `token.json` holds a long-lived refresh credential in plain text.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import tempfile

# Hik-Connect and EZVIZ share one backend; every API and auth host seen so far
# lives under one of these (api.hik-connect.com, apiisgp.ezvizlife.com,
# sgpauth.ezvizlife.com, ...).
ALLOWED_API_SUFFIXES = (".hik-connect.com", ".ezvizlife.com")

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class UntrustedHost(ValueError):
    """A host from a response or a file is outside what we accept."""


def check_api_domain(value) -> str:
    """Return `value` as a bare, lowercase vendor API host, or raise.

    Accepts only a host name — the callers build `https://{host}/...`, so a
    scheme, port, path or `user@` here would change where the request goes.
    """
    host = str(value or "").strip().lower()
    if not _HOSTNAME.match(host):
        raise UntrustedHost(f"not a bare host name: {value!r}")
    if not host.endswith(ALLOWED_API_SUFFIXES):
        raise UntrustedHost(f"API host outside the vendor domains: {host}")
    return host


def check_auth_url(value) -> str:
    """Same rule for the auth service, which is stored as a full https URL."""
    raw = str(value or "").strip()
    if not raw.lower().startswith("https://"):
        raise UntrustedHost(f"auth URL must be https: {value!r}")
    rest = raw[len("https://"):].rstrip("/")
    check_api_domain(rest)
    return f"https://{rest.lower()}"


def check_media_host(host, port=None) -> None:
    """Raise unless every address `host` resolves to is public.

    The relay is a plain TCP connection to whatever the cloud names. Inside a
    container network a private address would point it at a neighbour service.
    """
    name = str(host or "").strip().strip("[]")
    if not name:
        raise UntrustedHost("empty relay host")
    try:
        infos = socket.getaddrinfo(name, port, type=socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise UntrustedHost(f"relay host does not resolve: {name}") from err
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if not addr.is_global:
            raise UntrustedHost(f"relay host {name} resolves to non-public {addr}")


def write_private(path, text: str) -> None:
    """Write `text` to `path` atomically, mode 0600.

    `mkstemp` creates the file 0600 in the same directory, so `os.replace` is
    atomic and a reader never sees a half-written file — the proxy re-reads
    the token on every connection while the refresher rewrites it.
    """
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_private_json(path, data, **dump_kwargs) -> None:
    """`write_private` for a JSON document."""
    write_private(path, json.dumps(data, **dump_kwargs))
