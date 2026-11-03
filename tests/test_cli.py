from unittest.mock import patch

import pytest

from backend.main import main


def test_cli_mock_json(capsys):
    with patch("sys.argv", ["cloudsentinel", "--mock", "--report", "json"]):
        main()
    captured = capsys.readouterr()
    assert '"tool": "CloudSentinel"' in captured.out
    assert '"total_findings": 5' in captured.out


def test_cli_output_file(tmp_path):
    out_file = tmp_path / "report.csv"
    with patch("sys.argv", ["cloudsentinel", "--mock", "--report", "csv", "-o", str(out_file)]):
        main()
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "Finding ID,Cloud Provider,Service" in content


def test_cli_fail_on_threshold_breach():
    with patch("sys.argv", ["cloudsentinel", "--mock", "--fail-on", "high"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


def test_cli_fail_on_threshold_pass():
    with patch("sys.argv", ["cloudsentinel", "--mock", "--fail-on", "critical"]):
        main()


def test_cli_no_targets(capsys):
    with patch("sys.argv", ["cloudsentinel"]):
        main()
    captured = capsys.readouterr()
    assert "Please specify at least one target to scan" in captured.out
