import json
import os
import pickle
import subprocess
import sys
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest


def document(path="Document/book.pdf"):
    return {"entry_path": path, "entry_type": "document", "modified_date": "2026-10-08T08:00:00Z"}


@pytest.fixture
def syncing_device(device):
    device.assume_yes = True
    device.set_datetime = Mock()
    device.new_folder = Mock()
    device.traverse_folder_recursively = Mock(return_value=[])
    device.traverse_folder = Mock(return_value=[])
    device.download = Mock(return_value=b"%PDF fixture")
    device.upload_file = Mock()
    device.delete_document = Mock()
    device.delete_folder = Mock()
    return device


@pytest.mark.parametrize("remote_path", [
    "Document/../outside.pdf", "Document/sub/../../outside.pdf",
    "Document/..\\outside.pdf", "Document/C:outside.pdf", "/Document/outside.pdf",
    "Document-other/outside.pdf",
])
def test_sync_rejects_unsafe_device_paths_before_downloading(syncing_device, tmp_path, remote_path):
    root = tmp_path / "sync"
    root.mkdir()
    syncing_device.traverse_folder_recursively.return_value = [document(remote_path)]
    with pytest.raises(ValueError):
        syncing_device.sync(str(root), "Document")
    syncing_device.download.assert_not_called()
    syncing_device.upload_file.assert_not_called()
    assert list(root.iterdir()) == []
    assert not (tmp_path / "outside.pdf").exists()


def symlink(link, target, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are unavailable for this user")


def test_sync_rejects_destination_symlink(syncing_device, tmp_path):
    root = tmp_path / "sync"
    root.mkdir()
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"keep")
    symlink(root / "book.pdf", outside)
    syncing_device.traverse_folder_recursively.return_value = [document()]
    with pytest.raises(ValueError, match="[Ss]ymlink"):
        syncing_device.sync(str(root), "Document")
    assert outside.read_bytes() == b"keep"
    syncing_device.download.assert_not_called()


def test_sync_rejects_symlink_directory_without_recursing(syncing_device, tmp_path):
    symlink(tmp_path / "loop", tmp_path, directory=True)
    with pytest.raises(ValueError, match="[Ss]ymlink"):
        syncing_device.sync(str(tmp_path), "Document")
    syncing_device.upload_file.assert_not_called()
    syncing_device.delete_document.assert_not_called()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junctions")
def test_sync_rejects_windows_junction_outside_root(syncing_device, tmp_path):
    root, outside = tmp_path / "sync", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "private.pdf").write_bytes(b"keep private")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "link"), str(outside)],
                   check=True, capture_output=True)
    with pytest.raises(ValueError):
        syncing_device.sync(str(root), "Document")
    syncing_device.upload_file.assert_not_called()


def test_sync_downloads_valid_nested_document(syncing_device, tmp_path):
    entries = [document("Document/Notes/book.pdf")]
    syncing_device.traverse_folder_recursively.return_value = entries
    syncing_device.traverse_folder.return_value = entries
    syncing_device.sync(str(tmp_path), "Document")
    assert (tmp_path / "Notes/book.pdf").read_bytes() == b"%PDF fixture"
    assert syncing_device.load_checkpoint(tmp_path) == entries
    assert json.loads((tmp_path / ".sync").read_text())["version"] == 1


@pytest.mark.parametrize("protocol", [0, 4])
def test_legacy_checkpoint_migrates_only_plain_data(device, tmp_path, protocol):
    entries = [document()]
    checkpoint = tmp_path / ".sync"
    checkpoint.write_bytes(pickle.dumps(entries, protocol=protocol))
    assert device.load_checkpoint(tmp_path) == entries
    assert json.loads(checkpoint.read_text()) == {"version": 1, "entries": entries}


def test_checkpoint_cannot_invoke_pickle_globals(device, tmp_path):
    class CallablePayload:
        def __reduce__(self):
            # Harmless callable; even built-in functions must never be invoked.
            return int, ("42",)

    content = pickle.dumps(CallablePayload())
    checkpoint = tmp_path / ".sync"
    checkpoint.write_bytes(content)
    with pytest.raises(ValueError, match="checkpoint"):
        device.load_checkpoint(tmp_path)
    assert checkpoint.read_bytes() == content


@pytest.mark.parametrize("data", [
    {"version": 2, "entries": []}, {"version": 1, "entries": {}},
    {"version": 1, "entries": [{"entry_type": "document"}]},
    {"version": 1, "entries": [document("Document/../outside.pdf")]},
])
def test_invalid_checkpoint_is_not_treated_as_empty(device, tmp_path, data):
    checkpoint = tmp_path / ".sync"
    checkpoint.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="checkpoint"):
        device.load_checkpoint(tmp_path)


def test_failed_checkpoint_replace_preserves_previous_state(device, tmp_path, monkeypatch):
    device.sync_checkpoint(tmp_path, [document()])
    checkpoint = tmp_path / ".sync"
    original = checkpoint.read_bytes()
    monkeypatch.setattr(os, "replace", Mock(side_effect=OSError("disk failure")))
    with pytest.raises(OSError, match="disk failure"):
        device.sync_checkpoint(tmp_path, [])
    assert checkpoint.read_bytes() == original
    assert list(tmp_path.iterdir()) == [checkpoint]


def test_checkpoint_symlink_is_not_read(device, tmp_path):
    root = tmp_path / "sync"
    root.mkdir()
    target = tmp_path / "other"
    target.write_bytes(pickle.dumps([]))
    symlink(root / ".sync", target)
    with pytest.raises(ValueError, match="[Ss]ymlink"):
        device.load_checkpoint(root)


def test_legacy_checkpoint_cannot_use_cached_extension(device, tmp_path):
    import copyreg

    code = 249
    previous = copyreg._extension_cache.get(code)
    copyreg._extension_cache[code] = int
    try:
        # EXT1 refers directly to an existing callable in the extension cache.
        (tmp_path / ".sync").write_bytes(b"\x80\x02\x82" + bytes([code]) + b".")
        with pytest.raises(ValueError, match="checkpoint"):
            device.load_checkpoint(tmp_path)
    finally:
        if previous is None:
            copyreg._extension_cache.pop(code, None)
        else:
            copyreg._extension_cache[code] = previous


def test_new_local_document_is_uploaded(syncing_device, tmp_path):
    local = tmp_path / "book.pdf"
    local.write_bytes(b"local PDF")
    syncing_device.traverse_folder.return_value = [document()]
    syncing_device.sync(str(tmp_path), "Document")
    syncing_device.upload_file.assert_called_once_with(local, "Document/book.pdf")
    syncing_device.download.assert_not_called()


def test_newer_local_change_wins_sync_conflict(syncing_device, tmp_path):
    local = tmp_path / "book.pdf"
    local.write_bytes(b"newer local PDF")
    stamp = datetime(2026, 10, 8, 10, tzinfo=timezone.utc).timestamp()
    os.utime(local, (stamp, stamp))
    syncing_device.sync_checkpoint(tmp_path, [document()])
    remote = {**document(), "modified_date": "2026-10-08T09:00:00Z"}
    syncing_device.traverse_folder_recursively.return_value = [remote]
    syncing_device.traverse_folder.return_value = [remote]
    syncing_device.sync(str(tmp_path), "Document")
    syncing_device.upload_file.assert_called_once_with(local, "Document/book.pdf")
    syncing_device.download.assert_not_called()
    assert local.read_bytes() == b"newer local PDF"


def test_remote_deletion_removes_only_unchanged_local_document(syncing_device, tmp_path):
    local = tmp_path / "book.pdf"
    local.write_bytes(b"old PDF")
    stamp = datetime(2026, 10, 8, 8, tzinfo=timezone.utc).timestamp()
    os.utime(local, (stamp, stamp))
    syncing_device.sync_checkpoint(tmp_path, [document()])
    syncing_device.sync(str(tmp_path), "Document")
    assert not local.exists()
    syncing_device.delete_document.assert_not_called()


def test_failed_transfer_does_not_advance_checkpoint(syncing_device, tmp_path, monkeypatch):
    (tmp_path / "book.pdf").write_bytes(b"local PDF")
    syncing_device.sync_checkpoint(tmp_path, [])
    original = (tmp_path / ".sync").read_bytes()
    syncing_device.upload_file.side_effect = OSError("connection lost")
    progress = Mock()
    monkeypatch.setattr("dptrp1.dptrp1.tqdm", progress)
    with pytest.raises(OSError, match="connection lost"):
        syncing_device.sync(str(tmp_path), "Document")
    assert (tmp_path / ".sync").read_bytes() == original
    progress.return_value.close.assert_called_once()
