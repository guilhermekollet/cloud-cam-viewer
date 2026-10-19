"""Where the password, the session and the relay connection are allowed to go.

Each test pins one guard from `cloudcam.safety`: a regional redirect to a
foreign host must not get the password again, a token pointing elsewhere is
not resumed, the relay never connects to a private address, and secrets are
written atomically and owner-only. No network: every request is faked.
"""
import json
import os
import socket
import stat
import time
from types import SimpleNamespace

import pytest

from cloudcam import cli, identity, keys
from cloudcam import decrypt_proxy as dp
from cloudcam.client import CloudClient
from cloudcam.safety import (
    UntrustedHost,
    check_api_domain,
    check_auth_url,
    check_media_host,
    write_private,
)
from cloudcam.settings import Settings, set_active


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDCAM_FEATURE_CODE", "f" * 32)
    set_active(Settings(token_file=str(tmp_path / "token.json"),
                        camkey_file=str(tmp_path / "cam_keys.json")))
    identity.reset_cache()
    yield
    identity.reset_cache()
    set_active(Settings())


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


# ── API hosts ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("host", [
    "api.hik-connect.com",
    "apiisgp.ezvizlife.com",
    "sgpauth.ezvizlife.com",
    "APIIEU.EZVIZLIFE.COM",
])
def test_vendor_api_hosts_are_accepted(host):
    assert check_api_domain(host) == host.lower()


@pytest.mark.parametrize("host", [
    "evil.example",
    "api.hik-connect.com.evil.example",
    "hik-connect.com",                 # the bare domain is not an API host
    "evilhik-connect.com",
    "https://api.hik-connect.com",
    "api.hik-connect.com:8443",
    "user@api.hik-connect.com",
    "api.hik-connect.com/x",
    "",
    None,
])
def test_anything_else_is_refused(host):
    with pytest.raises(UntrustedHost):
        check_api_domain(host)


def test_auth_url_must_be_https_on_a_vendor_host():
    assert check_auth_url("https://sgpauth.ezvizlife.com/") == "https://sgpauth.ezvizlife.com"
    for bad in ("http://sgpauth.ezvizlife.com", "https://auth.evil.example"):
        with pytest.raises(UntrustedHost):
            check_auth_url(bad)


def test_region_redirect_to_a_foreign_host_does_not_resend_the_password():
    c = CloudClient("a@b.c", "pw", platform="hikconnect")
    posts = []

    def post(url, **kw):
        posts.append(url)
        return _Resp({"meta": {"code": 1100},
                      "loginArea": {"apiDomain": "api.evil.example"}})

    c.session.post = post
    with pytest.raises(UntrustedHost):
        c.login()
    # Only the first request, to the vendor host; the redirect never got one.
    assert posts == ["https://api.hik-connect.com/v3/users/login/v2"]


def test_login_answer_naming_a_foreign_api_domain_is_refused():
    c = CloudClient("a@b.c", "pw", platform="ezviz")
    c.session.post = lambda url, **kw: _Resp({
        "meta": {"code": 200},
        "loginSession": {"sessionId": "SID", "rfSessionId": "RF"},
        "loginArea": {"apiDomain": "api.evil.example"},
    })
    with pytest.raises(UntrustedHost):
        c.login()
    assert c.api_url == "apiisgp.ezvizlife.com"


def test_token_pointing_elsewhere_is_not_resumed(tmp_path):
    path = tmp_path / "token.json"
    path.write_text(json.dumps({
        "session_id": "SID", "rf_session_id": "RF", "api_url": "api.evil.example",
        "platform": "ezviz", "feature_code": "f" * 32, "session_time": time.time(),
    }))
    c = CloudClient("a@b.c", "pw", platform="ezviz")
    assert c.load_token(str(path)) is False
    assert c.session_id is None
    assert "sessionId" not in c.session.headers


def test_proxy_refuses_a_token_with_a_foreign_host(tmp_path, monkeypatch):
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"username": "a@b.c", "api_url": "api.evil.example"}))
    monkeypatch.setattr(dp, "get_active", lambda: SimpleNamespace(token_file=str(path)))
    monkeypatch.setattr(dp, "EzvizClient", lambda *a, **k: pytest.fail("client built"))
    with pytest.raises(UntrustedHost):
        dp._make_client()


# ── relay host ──────────────────────────────────────────────────────────

def _resolves_to(monkeypatch, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (family, socket.SOCK_STREAM, 6, "", (address, 0))])


@pytest.mark.parametrize("address", [
    "10.0.0.5", "172.18.0.2", "192.168.1.68", "127.0.0.1", "169.254.169.254",
    "::1", "fd00::1", "0.0.0.0", "203.0.113.10",  # last: TEST-NET-3, not global
])
def test_relay_on_a_private_address_is_refused(monkeypatch, address):
    _resolves_to(monkeypatch, address)
    with pytest.raises(UntrustedHost):
        check_media_host("vtm.example", 8554)


def test_relay_on_a_public_address_is_accepted(monkeypatch):
    _resolves_to(monkeypatch, "8.8.8.8")
    check_media_host("vtm.example", 8554)


def test_unresolvable_relay_is_refused(monkeypatch):
    def fail(*a, **k):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(UntrustedHost):
        check_media_host("vtm.example", 8554)


def test_proxy_checks_the_relay_host_before_building_the_url(monkeypatch):
    built = []
    monkeypatch.setattr(dp, "_unchecked_build_vtm_url",
                        lambda host, port, *a, **k: built.append(host) or "ysproto://x")
    _resolves_to(monkeypatch, "172.18.0.2")
    with pytest.raises(UntrustedHost):
        dp._cs.build_vtm_url("vtm.example", 8554, "SERIAL", "", "TOKEN")
    assert built == []

    _resolves_to(monkeypatch, "8.8.8.8")
    assert dp._cs.build_vtm_url("vtm.example", 8554, "SERIAL", "", "TOKEN") == "ysproto://x"
    assert built == ["vtm.example"]


def test_substream_keeps_the_relay_check(monkeypatch):
    monkeypatch.setattr(dp, "_unchecked_build_vtm_url",
                        lambda *a, **k: "ysproto://x/live?stream=1&dev=S")
    monkeypatch.setattr(dp, "_orig_build_vtm_url", None)
    try:
        dp.set_substream(True)
        _resolves_to(monkeypatch, "10.0.0.5")
        with pytest.raises(UntrustedHost):
            dp._cs.build_vtm_url("vtm.example", 8554, "S", "", "T")
        _resolves_to(monkeypatch, "8.8.8.8")
        assert "stream=2" in dp._cs.build_vtm_url("vtm.example", 8554, "S", "", "T")
    finally:
        dp.set_substream(False)


# ── secrets on disk ─────────────────────────────────────────────────────

def test_token_is_written_owner_only_and_atomically(tmp_path):
    path = tmp_path / "token.json"
    path.write_text("{}")
    os.chmod(path, 0o644)
    c = CloudClient("a@b.c", "pw", platform="ezviz")
    c.session_id, c.rf_session_id, c.session_time = "SID", "RF", 1.0
    c.save_token(str(path))

    assert _mode(path) == 0o600
    assert json.loads(path.read_text())["rf_session_id"] == "RF"
    assert [p.name for p in tmp_path.iterdir()] == ["token.json"]  # no .tmp left


def test_failed_write_keeps_the_previous_file(tmp_path, monkeypatch):
    path = tmp_path / "token.json"
    path.write_text('{"session_id": "OLD"}')

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        write_private(path, '{"session_id": "NEW"}')
    assert json.loads(path.read_text()) == {"session_id": "OLD"}
    assert [p.name for p in tmp_path.iterdir()] == ["token.json"]


def test_camera_keys_are_owner_only(tmp_path):
    keys.save({"SERIAL1": "ABCDEF"})
    path = tmp_path / "cam_keys.json"
    assert _mode(path) == 0o600
    assert keys.load() == {"SERIAL1": "ABCDEF"}


def test_feature_code_file_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.delenv("CLOUDCAM_FEATURE_CODE")
    identity.reset_cache()
    identity.feature_code()
    assert _mode(tmp_path / "feature_code.txt") == 0o600


# ── refresh and CLI ─────────────────────────────────────────────────────

def test_refresh_failure_is_reported_not_swallowed(capsys):
    c = CloudClient("a@b.c", "pw", platform="ezviz")
    c.session.put = lambda url, **kw: _Resp({"meta": {"code": 1014}})
    c.login = lambda: pytest.fail("no password login without allow_login")
    with pytest.raises(RuntimeError, match="meta.code 1014"):
        c.refresh_session(allow_login=False)
    assert "session refresh failed (meta.code 1014)" in capsys.readouterr().err


def test_keys_command_does_not_print_the_codes(monkeypatch, capsys):
    fake = SimpleNamespace(
        fetch_keys=lambda *a, **k: keys.FetchResult(fetched={"SERIAL1": "ABCDEF"}),
        close=lambda: None,
    )
    monkeypatch.setattr(cli, "_cam", lambda args: fake)
    assert cli.main(["keys"]) == 0
    out = capsys.readouterr().out
    assert "SERIAL1" in out
    assert "ABCDEF" not in out


# ── verification code case ──────────────────────────────────────────────

def test_typed_code_keeps_its_case():
    keys.set_code("SERIAL1", " Abc12de ")
    assert keys.load() == {"SERIAL1": "Abc12de"}


def test_cloud_code_keeps_its_case():
    c = CloudClient("a@b.c", "pw", platform="ezviz")
    c.session.get = lambda url, **kw: _Resp({"meta": {"code": 200}, "devAuthCode": "Abc12de"})
    assert c.get_verification_code("SERIAL1") == "Abc12de"


def test_key_bytes_follow_the_code_exactly():
    # The decryptors pad the code itself to 16 bytes; case is part of the key.
    assert dp.HevcRtpDecryptor("Abc12de").key != dp.HevcRtpDecryptor("ABC12DE").key
