from tb_collector.config import load_config


def test_load_config(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "base_url: http://localhost:8000/api/v1\n"
        "email: test@acme.example\n"
        "password: secret\n"
        "collector_id: kali-01\n"
        "asset_name: kali-box\n"
        "log_path: /var/log/auth.log\n"
        "threshold: 8\n"
        "window_seconds: 45\n"
        "cooldown_seconds: 200\n"
    )
    c = load_config(str(p))
    assert c.base_url == "http://localhost:8000/api/v1"
    assert c.email == "test@acme.example"
    assert c.collector_id == "kali-01"
    assert c.threshold == 8
    assert c.window_seconds == 45
    assert c.effective_paths() == ["/var/log/auth.log"]


def test_multiple_log_paths(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "base_url: x\nemail: a@b.c\npassword: x\ncollector_id: k\n"
        "log_paths:\n  - /var/log/auth.log\n  - /var/log/nginx/access.log\n"
    )
    c = load_config(str(p))
    assert c.effective_paths() == ["/var/log/auth.log", "/var/log/nginx/access.log"]


def test_missing_paths_raises(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("base_url: x\nemail: a@b.c\npassword: x\ncollector_id: k\n")
    try:
        load_config(str(p))
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_defaults_applied(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "base_url: http://localhost:8000/api/v1\n"
        "email: a@b.c\n"
        "password: x\n"
        "collector_id: k\n"
        "log_path: /var/log/auth.log\n"
    )
    c = load_config(str(p))
    assert c.threshold == 10
    assert c.window_seconds == 60
    assert c.cooldown_seconds == 300
    assert c.asset_name is None
