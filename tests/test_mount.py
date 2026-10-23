import errno
import os
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

if sys.platform != "linux":
    pytest.skip("FUSE tests use the Linux FUSE 2 library", allow_module_level=True)

from dptrp1.cli.dptmount import DptTablet, FileHandle, FuseOSError


def handle(new=True):
    fs = Mock()
    fs._map_local_remote.return_value = SimpleNamespace(
        remote_path="Document", item={"entry_path": "Document/book.pdf"},
    )
    fs.dpt.download.return_value = b"abcdef"
    return FileHandle(fs, "/book.pdf", new=new), fs


def test_partial_write_preserves_tail():
    file, fs = handle()
    file.write(b"abcdef", 0)
    file.write(b"XY", 1)
    assert file.read(20, 0) == b"aXYdef"
    file.flush()
    assert fs.dpt.upload.call_args.args[0].getvalue() == b"aXYdef"


def test_write_after_read_uses_mutable_buffer():
    file, _ = handle(new=False)
    assert file.read(6, 0) == b"abcdef"
    assert isinstance(file.read(6, 0), bytes)  # fusepy passes this to ctypes.memmove
    file.write(b"XY", 1)
    assert file.read(6, 0) == b"aXYdef"


def test_write_loads_existing_data_before_changing_it():
    file, _ = handle(new=False)
    file.write(b"XY", 1)
    assert file.read(6, 0) == b"aXYdef"


def test_write_beyond_end_fills_gap():
    file, _ = handle()
    file.write(b"x", 3)
    assert file.read(10, 0) == b"\x00\x00\x00x"


def test_failed_upload_remains_dirty_for_retry():
    file, fs = handle()
    file.write(b"fixture", 0)
    fs.dpt.upload.side_effect = OSError("connection lost")
    with pytest.raises(OSError):
        file.flush()
    assert file.status == "dirty"
    fs._add_remote_path_to_tree.assert_not_called()


def test_open_raises_permission_error_for_unsupported_write_mode():
    tablet = DptTablet.__new__(DptTablet)
    with pytest.raises(FuseOSError) as error:
        tablet.open("/book.pdf", os.O_WRONLY)
    assert error.value.errno == errno.EACCES


def test_rename_uses_existing_move_api():
    from dptrp1.dptrp1 import DigitalPaper

    tablet = DptTablet.__new__(DptTablet)
    tablet.dpt = Mock(spec=DigitalPaper)
    source = SimpleNamespace(remote_path="Document/book.pdf", item={"entry_type": "document"})
    target = SimpleNamespace(remote_path="Document/Notes")
    tablet._map_local_remote = Mock(side_effect=[source, target, None])
    tablet._remove_node = Mock()
    tablet._add_remote_path_to_tree = Mock(return_value=SimpleNamespace(item={"entry_type": "document"}))
    tablet.rename("/book.pdf", "/Notes/renamed.pdf")
    tablet.dpt.move_file.assert_called_once_with("Document/book.pdf", "Document/Notes/renamed.pdf")
    tablet._remove_node.assert_called_once_with(source)


@pytest.mark.parametrize("source_type,destination,expected", [
    ("folder", None, errno.EOPNOTSUPP), ("document", object(), errno.EEXIST),
])
def test_unsupported_rename_does_not_modify_device(source_type, destination, expected):
    tablet = DptTablet.__new__(DptTablet)
    tablet.dpt = Mock()
    source = SimpleNamespace(remote_path="Document/source", item={"entry_type": source_type})
    parent = SimpleNamespace(remote_path="Document")
    tablet._map_local_remote = Mock(side_effect=[source, parent, destination])
    with pytest.raises(FuseOSError) as error:
        tablet.rename("/source", "/destination")
    assert error.value.errno == expected
    assert tablet.dpt.mock_calls == []


def test_repeated_flush_metadata_refresh_does_not_duplicate_tree_nodes():
    from anytree import Node

    tablet = DptTablet.__new__(DptTablet)
    tablet.root = Node("Document", localpath="/", remote_path="Document")
    tablet.dpt = Mock()
    tablet.dpt._resolve_object_by_path.return_value = {
        "entry_name": "book.pdf", "entry_path": "Document/book.pdf", "entry_type": "document",
    }
    tablet._get_lstat = Mock(return_value={"st_size": 10})
    first = tablet._add_remote_path_to_tree(tablet.root, "Document/book.pdf")
    tablet._get_lstat.return_value = {"st_size": 20}
    second = tablet._add_remote_path_to_tree(tablet.root, "Document/book.pdf")
    assert first is second
    assert len(tablet.root.children) == 1
    assert second.lstat["st_size"] == 20


def test_buffer_size_is_visible_before_flush():
    file, _ = handle()
    tablet = DptTablet.__new__(DptTablet)
    tablet.handle = {1: file}
    tablet.files = {"/book.pdf": {"st_size": 0}}
    tablet.write("/book.pdf", b"abc", 2, 1)
    assert tablet.getattr("/book.pdf")["st_size"] == 5
