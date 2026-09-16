"""TLS front-end packaging: nginx site, UFW profile, setup and maintainer scripts.

The daemon binds to loopback and nginx terminates TLS on 8767 with the device
certificate wlanpi-core generates. These tests pin the pieces the package
ships to make that true: the site file proxies to the daemon's default
host:port with SSE-safe settings, the UFW profile opens only the TLS port, the
nginx setup script links/unlinks exactly and never leaves nginx broken, the
UFW setup script closes the cleartext port and opens the TLS one, and the
maintainer scripts wire it all together.
"""

import inspect
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from wlanpi_mcp.config import Settings
from wlanpi_mcp.server import create_server

REPO = Path(__file__).parent.parent
INSTALL = REPO / "install/etc/wlanpi-mcp"
SITE = INSTALL / "nginx/wlanpi_mcp_tls.conf"
NGINX_SETUP = INSTALL / "nginx/wlanpi-mcp-nginx-setup.sh"
UFW_RULES = INSTALL / "ufw/wlanpi-mcp.rules"
UFW_VERSION = INSTALL / "ufw/current-rules-version"
UFW_SETUP = INSTALL / "ufw/wlanpi-mcp-ufw-rules-setup.sh"
CONFIG_EXAMPLE = INSTALL / "config.env.example"
DEBIAN = REPO / "debian"
POSTINST = DEBIAN / "postinst"
POSTRM = DEBIAN / "postrm"
CONTROL = DEBIAN / "control"
INSTALL_LIST = DEBIAN / "wlanpi-mcp.install"
DIRS = DEBIAN / "wlanpi-mcp.dirs"

CERT = "/etc/nginx/ssl/self-signed-wlanpi.cert"
KEY = "/etc/nginx/ssl/self-signed-wlanpi.key"
TLS_PORT = 8767
DAEMON_PORT = 8766
SITES_ENABLED_LINK = "/etc/nginx/sites-enabled/wlanpi_mcp_tls.conf"


def _run(script, *args, env=None, cwd=None):
    full_env = dict(os.environ)
    full_env.update(env or {})
    return subprocess.run(
        ["bash", str(script), *args],
        env=full_env,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _stub(bin_dir: Path, name: str, body: str) -> Path:
    """Write an executable stub named `name` into bin_dir."""
    path = bin_dir / name
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# --- Defaults: daemon on loopback ------------------------------------------


def test_daemon_defaults_to_loopback():
    settings = Settings(_env_file=None)
    assert settings.WLANPI_MCP_HOST == "127.0.0.1"
    assert settings.WLANPI_MCP_PORT == DAEMON_PORT
    assert inspect.signature(create_server).parameters["host"].default == "127.0.0.1"
    assert inspect.signature(create_server).parameters["port"].default == DAEMON_PORT


def test_config_example_binds_loopback():
    text = CONFIG_EXAMPLE.read_text()
    assert re.search(r"^WLANPI_MCP_HOST=127\.0\.0\.1$", text, re.M)
    assert re.search(rf"^WLANPI_MCP_PORT={DAEMON_PORT}$", text, re.M)


# --- nginx site file -------------------------------------------------------


def _server_block(conf: str) -> str:
    m = re.search(r"^server\s*\{", conf, re.M)
    assert m, "no server block"
    depth, start = 0, m.start()
    for i in range(m.end() - 1, len(conf)):
        if conf[i] == "{":
            depth += 1
        elif conf[i] == "}":
            depth -= 1
            if depth == 0:
                return conf[start : i + 1]
    raise AssertionError("unbalanced braces")


def test_site_listens_tls_only_on_8767():
    block = _server_block(SITE.read_text())
    listens = re.findall(r"^\s*listen\s+([^;]+);", block, re.M)
    assert listens == [f"{TLS_PORT} ssl"], listens


def test_site_uses_core_device_certificate():
    conf = SITE.read_text()
    assert f"ssl_certificate     {CERT};" in conf
    assert f"ssl_certificate_key {KEY};" in conf
    assert re.search(r"^\s*ssl_protocols TLSv1\.2 TLSv1\.3;", conf, re.M)


def test_site_proxies_to_daemon_default_host_port():
    conf = SITE.read_text()
    settings = Settings(_env_file=None)
    targets = re.findall(r"^\s*proxy_pass\s+([^;]+);", conf, re.M)
    assert targets == [f"http://{settings.WLANPI_MCP_HOST}:{settings.WLANPI_MCP_PORT}"]


def test_site_is_sse_safe():
    conf = SITE.read_text()
    for directive in (
        "proxy_http_version 1.1;",
        'proxy_set_header Connection "";',
        "proxy_buffering off;",
        "proxy_cache off;",
        "proxy_read_timeout 1h;",
        "proxy_send_timeout 1h;",
        "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_set_header X-Forwarded-Proto $scheme;",
    ):
        assert directive in conf, directive


def test_site_logs_do_not_depend_on_core_log_format():
    conf = SITE.read_text()
    assert "json_combined" not in conf
    assert re.search(r"^\s*access_log /var/log/wlanpi-mcp/\S+ combined;", conf, re.M)
    assert re.search(r"^\s*error_log /var/log/wlanpi-mcp/\S+;", conf, re.M)
    # The package must create the log directory (nginx -t opens the logs).
    assert "var/log/wlanpi-mcp" in DIRS.read_text().split()


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx binary not available")
@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not available")
def test_site_passes_nginx_config_test(tmp_path):
    """Validate the real site file with `nginx -t` against a throwaway cert."""
    cert, key = tmp_path / "wlanpi.cert", tmp_path / "wlanpi.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=wlanpi.local",
        ],
        check=True,
        capture_output=True,
    )
    logs = tmp_path / "log"
    logs.mkdir()
    site = (
        SITE.read_text()
        .replace(CERT, str(cert))
        .replace(KEY, str(key))
        .replace("/var/log/wlanpi-mcp", str(logs))
    )
    (tmp_path / "site.conf").write_text(site)
    (tmp_path / "nginx.conf").write_text(
        f"pid {tmp_path}/nginx.pid;\nerror_log {logs}/main_error.log;\n"
        f"events {{}}\nhttp {{ include {tmp_path}/site.conf; }}\n"
    )
    proc = subprocess.run(
        ["nginx", "-t", "-q", "-p", str(tmp_path), "-c", str(tmp_path / "nginx.conf")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


# --- UFW profile -----------------------------------------------------------


def _profiles(text: str) -> dict:
    out, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            out[current] = {}
        elif "=" in line and current:
            k, v = line.split("=", 1)
            out[current][k] = v
    return out


def test_ufw_profiles_open_tls_port_only_and_keep_cleartext_name():
    profiles = _profiles(UFW_RULES.read_text())
    assert profiles["wlanpi-mcp-tls"]["ports"] == f"{TLS_PORT}/tcp"
    # Kept so `ufw delete allow wlanpi-mcp` can still resolve the name on
    # upgrade/removal; it is never allowed.
    assert profiles["wlanpi-mcp"]["ports"] == f"{DAEMON_PORT}/tcp"
    assert set(profiles) == {"wlanpi-mcp-tls", "wlanpi-mcp"}


def test_ufw_rules_version_bumped_for_tls():
    assert int(UFW_VERSION.read_text().strip()) >= 2


# --- nginx setup script ----------------------------------------------------


@pytest.fixture
def nginx_env(tmp_path):
    """Temp site source, sites-enabled dir and cert/key, no nginx/systemd."""
    src = tmp_path / "src" / "wlanpi_mcp_tls.conf"
    src.parent.mkdir()
    shutil.copy(SITE, src)
    enabled = tmp_path / "sites-enabled"
    cert, key = tmp_path / "wlanpi.cert", tmp_path / "wlanpi.key"
    cert.write_text("cert")
    key.write_text("key")
    env = {
        "WLANPI_MCP_NGINX_SITE_SRC": str(src),
        "WLANPI_MCP_NGINX_SITES_ENABLED": str(enabled),
        "WLANPI_MCP_NGINX_CERT": str(cert),
        "WLANPI_MCP_NGINX_KEY": str(key),
        "WLANPI_MCP_NGINX_NO_SYSTEM": "1",
    }
    return env, src, enabled / src.name


def test_nginx_apply_links_site(nginx_env):
    env, src, link = nginx_env
    proc = _run(NGINX_SETUP, "apply", env=env)
    assert proc.returncode == 0, proc.stderr
    assert link.is_symlink() and os.readlink(link) == str(src)


def test_nginx_apply_is_idempotent_and_repairs_wrong_link(nginx_env):
    env, src, link = nginx_env
    link.parent.mkdir()
    link.symlink_to("/nonexistent/other.conf")
    assert _run(NGINX_SETUP, "apply", env=env).returncode == 0
    assert os.readlink(link) == str(src)
    proc = _run(NGINX_SETUP, "apply", env=env)
    assert proc.returncode == 0
    assert "Linked" not in proc.stdout  # nothing to do the second time
    assert os.readlink(link) == str(src)


def test_nginx_apply_refuses_without_device_certificate(nginx_env):
    env, src, link = nginx_env
    Path(env["WLANPI_MCP_NGINX_KEY"]).unlink()
    proc = _run(NGINX_SETUP, "apply", env=env)
    assert proc.returncode == 1
    assert "certificate" in proc.stderr
    assert not link.exists() and not link.is_symlink()


def test_nginx_apply_refuses_without_site_source(nginx_env):
    env, src, link = nginx_env
    src.unlink()
    proc = _run(NGINX_SETUP, "apply", env=env)
    assert proc.returncode == 1
    assert not link.is_symlink()


def test_nginx_remove_unlinks_and_is_noop_when_absent(nginx_env):
    env, src, link = nginx_env
    assert _run(NGINX_SETUP, "apply", env=env).returncode == 0
    assert _run(NGINX_SETUP, "remove", env=env).returncode == 0
    assert not link.is_symlink()
    proc = _run(NGINX_SETUP, "remove", env=env)
    assert proc.returncode == 0 and proc.stdout == ""


def test_nginx_setup_usage():
    assert _run(NGINX_SETUP).returncode == 2
    assert _run(NGINX_SETUP, "bogus").returncode == 2


@pytest.fixture
def fake_system(tmp_path):
    """Stub nginx/ischroot/deb-systemd-invoke on PATH, recording calls."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    fail_flag = tmp_path / "nginx-t-fails"
    _stub(bin_dir, "ischroot", "exit 1\n")
    _stub(
        bin_dir,
        "nginx",
        f'echo "nginx $*" >> "{calls}"\n'
        f'if [ -e "{fail_flag}" ]; then echo "nginx: [emerg] bad" >&2; exit 1; fi\nexit 0\n',
    )
    _stub(
        bin_dir,
        "deb-systemd-invoke",
        f'echo "deb-systemd-invoke $*" >> "{calls}"\nexit 0\n',
    )
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}"}

    def recorded():
        return calls.read_text().splitlines() if calls.exists() else []

    return env, recorded, fail_flag


def test_nginx_apply_tests_config_and_reloads(nginx_env, fake_system):
    env, src, link = nginx_env
    sys_env, recorded, _ = fake_system
    env = {**env, **sys_env, "WLANPI_MCP_NGINX_NO_SYSTEM": "0"}
    proc = _run(NGINX_SETUP, "apply", env=env)
    assert proc.returncode == 0, proc.stderr
    assert link.is_symlink()
    assert "nginx -t" in recorded()
    assert "deb-systemd-invoke reload nginx.service" in recorded()


def test_nginx_apply_unlinks_when_config_test_fails(nginx_env, fake_system):
    """A broken site must not be left linked: that nginx also serves core."""
    env, src, link = nginx_env
    sys_env, recorded, fail_flag = fake_system
    fail_flag.touch()
    env = {**env, **sys_env, "WLANPI_MCP_NGINX_NO_SYSTEM": "0"}
    proc = _run(NGINX_SETUP, "apply", env=env)
    assert proc.returncode == 1
    assert "unlinked" in proc.stderr
    assert not link.is_symlink()
    assert not any("reload" in c or "restart" in c for c in recorded())


def test_nginx_remove_reloads(nginx_env, fake_system):
    env, src, link = nginx_env
    sys_env, recorded, _ = fake_system
    assert _run(NGINX_SETUP, "apply", env=env).returncode == 0
    env = {**env, **sys_env, "WLANPI_MCP_NGINX_NO_SYSTEM": "0"}
    assert _run(NGINX_SETUP, "remove", env=env).returncode == 0
    assert not link.is_symlink()
    assert "deb-systemd-invoke reload nginx.service" in recorded()


# --- UFW setup script ------------------------------------------------------


@pytest.fixture
def ufw_env(tmp_path):
    """Temp rules dir, apps dir and version marker, with a recording ufw stub."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    shutil.copy(UFW_RULES, rules_dir / "wlanpi-mcp.rules")
    shutil.copy(UFW_VERSION, rules_dir / "current-rules-version")
    apps_dir = tmp_path / "applications.d"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "ufw-calls.log"
    _stub(bin_dir, "ischroot", "exit 1\n")
    _stub(bin_dir, "ufw", f'echo "$*" >> "{calls}"\nexit 0\n')
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "WLANPI_MCP_UFW_RULES_DIR": str(rules_dir),
        "WLANPI_MCP_UFW_INSTALLED_VERSION_FILE": str(
            tmp_path / "installed-rules-version"
        ),
        "WLANPI_MCP_UFW_APPS_DIR": str(apps_dir),
        "WLANPI_MCP_UFW_LOGFILE": str(tmp_path / "firstboot.log"),
        "WLANPI_MCP_UFW_NO_ROOT_CHECK": "1",
    }

    def recorded():
        return calls.read_text().splitlines() if calls.exists() else []

    return env, apps_dir, recorded


def test_ufw_setup_opens_tls_and_closes_cleartext(ufw_env):
    env, apps_dir, recorded = ufw_env
    proc = _run(UFW_SETUP, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (apps_dir / "wlanpi-mcp").read_text() == UFW_RULES.read_text()
    calls = recorded()
    assert "allow wlanpi-mcp-tls" in calls
    assert "delete allow wlanpi-mcp" in calls
    assert "delete allow 8766/tcp" in calls
    assert "reload" in calls
    assert "allow wlanpi-mcp" not in calls  # cleartext profile is never opened
    assert calls.index("delete allow wlanpi-mcp") < calls.index("allow wlanpi-mcp-tls")
    assert (
        Path(env["WLANPI_MCP_UFW_INSTALLED_VERSION_FILE"]).read_text()
        == UFW_VERSION.read_text()
    )


def test_ufw_setup_is_idempotent_by_version(ufw_env):
    env, apps_dir, recorded = ufw_env
    assert _run(UFW_SETUP, env=env).returncode == 0
    first = len(recorded())
    proc = _run(UFW_SETUP, env=env)
    assert proc.returncode == 0
    assert len(recorded()) == first
    assert "up to date" in proc.stdout


def test_ufw_setup_reapplies_when_version_changes(ufw_env):
    env, apps_dir, recorded = ufw_env
    assert _run(UFW_SETUP, env=env).returncode == 0
    Path(env["WLANPI_MCP_UFW_INSTALLED_VERSION_FILE"]).write_text("1\n")
    first = len(recorded())
    assert _run(UFW_SETUP, env=env).returncode == 0
    assert len(recorded()) > first


def test_ufw_setup_skips_in_chroot(ufw_env, tmp_path):
    env, apps_dir, recorded = ufw_env
    _stub(tmp_path / "bin", "ischroot", "exit 0\n")
    proc = _run(UFW_SETUP, env=env)
    assert proc.returncode == 0
    assert recorded() == []
    assert not apps_dir.exists()


# --- Maintainer scripts and packaging lists --------------------------------


@pytest.mark.parametrize("script", [POSTINST, POSTRM], ids=lambda p: p.name)
def test_maintainer_scripts_parse(script):
    assert (
        subprocess.run(["sh", "-n", str(script)], capture_output=True).returncode == 0
    )


@pytest.mark.parametrize("script", [NGINX_SETUP, UFW_SETUP], ids=lambda p: p.name)
def test_setup_scripts_parse_and_are_executable(script):
    assert (
        subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0
    )
    assert os.access(script, os.X_OK)


def test_postinst_wires_nginx_and_ufw():
    text = POSTINST.read_text()
    assert "/etc/wlanpi-mcp/nginx/wlanpi-mcp-nginx-setup.sh" in text
    assert re.search(r'"\$NGINX_SETUP" apply', text)
    assert "/etc/wlanpi-mcp/ufw/wlanpi-mcp-ufw-rules-setup.sh" in text
    assert "wlanpi-mcp-ufw-first-boot.service" in text


def test_postinst_default_config_matches_example():
    text = POSTINST.read_text()
    m = re.search(r"<<EOCFG\n(.*?)EOCFG\n", text, re.S)
    assert m, "config heredoc not found"
    assert m.group(1) == CONFIG_EXAMPLE.read_text()


def test_postinst_migrates_default_bind_to_loopback(tmp_path):
    """The upgrade path moves a still-default 0.0.0.0 bind to loopback and
    leaves a custom bind alone. Exercise the exact grep/sed pair postinst
    uses rather than the (root-only, hardcoded-path) script itself."""
    text = POSTINST.read_text()
    grep = re.search(r"grep -qx '([^']+)' \"\$CONFIG_FILE\"", text)
    sed = re.search(r"sed -i '([^']+)' \"\$CONFIG_FILE\"", text)
    assert grep and sed
    for before, after in [
        ("WLANPI_MCP_HOST=0.0.0.0", "WLANPI_MCP_HOST=127.0.0.1"),
        ("WLANPI_MCP_HOST=10.0.0.5", "WLANPI_MCP_HOST=10.0.0.5"),
        ("WLANPI_MCP_HOST=127.0.0.1", "WLANPI_MCP_HOST=127.0.0.1"),
    ]:
        cfg = tmp_path / "config.env"
        cfg.write_text(
            f"WLANPI_CORE_URL=http://localhost:31415\n{before}\nWLANPI_MCP_PORT=8766\n"
        )
        shell = f"if grep -qx '{grep.group(1)}' \"$1\"; then sed -i '{sed.group(1)}' \"$1\"; fi"
        subprocess.run(["sh", "-c", shell, "sh", str(cfg)], check=True)
        assert cfg.read_text().splitlines()[1] == after


def test_postrm_removes_site_link_and_firewall_rules():
    text = POSTRM.read_text()
    assert f"rm -f {SITES_ENABLED_LINK}" in text
    assert "ufw delete allow wlanpi-mcp-tls" in text
    assert "ufw delete allow wlanpi-mcp " in text
    assert "rm -f /etc/ufw/applications.d/wlanpi-mcp" in text
    assert "rm -rf /var/log/wlanpi-mcp" in text


def test_nginx_setup_link_matches_postrm_cleanup():
    """postrm removes the link by literal path; keep it in step with the
    script's defaults so a rename can't leave a stale site behind."""
    text = NGINX_SETUP.read_text()
    assert "/etc/nginx/sites-enabled}" in text
    assert "/etc/wlanpi-mcp/nginx/wlanpi_mcp_tls.conf}" in text
    assert SITES_ENABLED_LINK == "/etc/nginx/sites-enabled/" + SITE.name


def test_control_depends_on_nginx_and_ufw():
    depends = re.search(r"^Depends: (.*)$", CONTROL.read_text(), re.M).group(1)
    assert "wlanpi-core" in depends
    assert "nginx-light | nginx-full | nginx-extras" in depends
    assert "ufw" in depends


def test_install_list_ships_every_etc_file():
    lines = [
        line.split()[0]
        for line in INSTALL_LIST.read_text().splitlines()
        if line.strip()
    ]
    shipped = {line for line in lines if line.startswith("install/")}
    on_disk = {
        str(p.relative_to(REPO))
        for p in INSTALL.rglob("*")
        if p.is_file() and p.name != "config.env.example"
    }
    assert on_disk == shipped


def test_ufw_first_boot_unit_is_shipped():
    """postinst enables this oneshot inside a chroot (image build) so the
    firewall rules get applied on first boot; it must actually be installed."""
    lines = [
        line.split() for line in INSTALL_LIST.read_text().splitlines() if line.strip()
    ]
    assert ["debian/wlanpi-mcp-ufw-first-boot.service", "/lib/systemd/system"] in lines
    unit = (DEBIAN / "wlanpi-mcp-ufw-first-boot.service").read_text()
    assert "ExecStart=/etc/wlanpi-mcp/ufw/wlanpi-mcp-ufw-rules-setup.sh" in unit
    assert (
        "/lib/systemd/system/wlanpi-mcp-ufw-first-boot.service" in POSTINST.read_text()
    )
