import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from dptrp1.cli import dptrp1 as cli


@pytest.mark.parametrize("arguments,expected", [
    (["--help"], "Remote control for Sony DPT-RP1"),
    (["help", "upload"], "Upload a local document"),
    (["help", "sync"], "Synchronize all PDF documents"),
])
def test_help_does_not_connect_to_reader(monkeypatch, capsys, arguments, expected):
    constructor = Mock(side_effect=AssertionError("Help must not access a reader"))
    monkeypatch.setattr(cli, "DigitalPaper", constructor)
    monkeypatch.setattr(sys, "argv", ["dptrp1", *arguments])
    if arguments == ["--help"]:
        with pytest.raises(SystemExit) as result:
            cli.main()
        assert result.value.code == 0
    else:
        cli.main()
    assert expected in capsys.readouterr().out
    constructor.assert_not_called()


@pytest.mark.parametrize("remote,expected", [
    (None, "Document/sample.pdf"),
    ("Notes/sample.pdf", "Document/Notes/sample.pdf"),
    ("Document/Notes/sample.pdf", "Document/Notes/sample.pdf"),
])
def test_upload_targets_document_root(tmp_path, remote, expected):
    device = Mock()
    local = str(tmp_path / "sample.pdf")
    cli.do_upload(device, local, *([] if remote is None else [remote]))
    device.upload_file.assert_called_once_with(local, expected)


def test_unknown_command_exits_before_device_access(monkeypatch):
    constructor = Mock()
    monkeypatch.setattr(cli, "DigitalPaper", constructor)
    monkeypatch.setattr(sys, "argv", ["dptrp1", "not-a-command"])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 2
    constructor.assert_not_called()


def test_install_print_service_compiles_applet_without_device(monkeypatch, tmp_path):
    constructor = Mock(side_effect=AssertionError("Installer must not access a reader"))
    monkeypatch.setattr(cli, "DigitalPaper", constructor)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    run = Mock()
    monkeypatch.setattr(cli.subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["dptrp1", "--addr", "10.0.0.1", "install-print-service"])
    cli.main()
    (command,), kwargs = run.call_args
    assert command[:2] == ["osacompile", "-o"]
    assert command[2] == str(tmp_path / "Library" / "PDF Services" / "Send to Digital Paper.app")
    assert "--addr 10.0.0.1 upload" in kwargs["input"]
    constructor.assert_not_called()


def test_install_print_service_refuses_other_platforms(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(SystemExit):
        cli.do_install_print_service([])


def test_download_into_directory_without_trailing_separator(tmp_path):
    destination = tmp_path / "downloads"
    destination.mkdir()
    cli.do_download(Mock(download=Mock(return_value=b"pdf")), "Document/book.pdf", str(destination))
    assert (destination / "book.pdf").read_bytes() == b"pdf"
    assert not (tmp_path / "downloadsbook.pdf").exists()


@pytest.mark.parametrize("content", ["{", "{}", "[]", '"network"'])
@pytest.mark.parametrize("operation", [cli.do_add_wifi, cli.do_delete_wifi])
def test_invalid_wifi_configuration_does_not_change_device(tmp_path, content, operation):
    config = tmp_path / "wifi.json"
    config.write_text(content)
    device = Mock()
    with pytest.raises(ValueError):
        operation(device, str(config))
    assert device.mock_calls == []


def test_missing_wifi_configuration_reports_file_error(tmp_path):
    with pytest.raises(ValueError, match="configuration"):
        cli.do_add_wifi(Mock(), str(tmp_path / "missing.json"))
