from pathlib import Path

import pytest

from dptrp1.dptrp1 import local_path_for


def test_device_path_maps_under_local_folder(tmp_path):
    local = local_path_for(tmp_path, "Document", "Document/Notes/sample.pdf")
    assert local == tmp_path.resolve() / "Notes" / "sample.pdf"


def test_remote_folder_itself_maps_to_local_folder(tmp_path):
    assert local_path_for(tmp_path, "Document", "Document") == tmp_path.resolve()


@pytest.mark.parametrize("remote_path", [
    "Document/../../.bashrc",
    "Document/Notes/../../../etc/passwd",
    "Document/..",
])
def test_device_path_escaping_local_folder_is_refused(tmp_path, remote_path):
    with pytest.raises(ValueError):
        local_path_for(tmp_path, "Document", remote_path)


def test_symlink_inside_local_folder_pointing_out_is_refused(tmp_path):
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    root = tmp_path / "sync"
    root.mkdir()
    (root / "link").symlink_to(outside)
    with pytest.raises(ValueError):
        local_path_for(root, "Document", "Document/link/sample.pdf")
