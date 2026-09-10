from stealthix.config import load_config


def test_load_config_yaml(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("proxy: http://localhost:8080\nheaders:\n  X-Test: value\n")
    config = load_config(path)
    assert config["proxy"] == "http://localhost:8080"
    assert config["headers"]["X-Test"] == "value"


def test_load_config_toml(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('proxy = "http://localhost:8080"\n')
    config = load_config(path)
    assert config["proxy"] == "http://localhost:8080"


def test_load_config_json(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"proxy": "http://localhost:8080"}')
    config = load_config(path)
    assert config["proxy"] == "http://localhost:8080"
