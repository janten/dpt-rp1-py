"""Path validation and data-only, atomic synchronization checkpoints."""

import io
import json
import os
import pickle
import pickletools
import tempfile
import unicodedata
from datetime import datetime
from pathlib import Path, PurePosixPath


def remote_path(value):
    """Validate a device path before interpreting it as a local filesystem path."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("Invalid sync path")
    value = unicodedata.normalize("NFC", value).rstrip("/")
    parts = value.split("/")
    if any(part in ("", ".", "..") or ":" in part for part in parts):
        raise ValueError(f"Unsafe sync path: {value!r}")
    return PurePosixPath(value)


def local_path(root, remote_root, entry_path):
    root = Path(root).resolve()
    try:
        relative = remote_path(entry_path).relative_to(remote_path(remote_root))
    except ValueError as exc:
        raise ValueError(f"Invalid path in sync listing: {entry_path!r}") from exc
    destination = root
    for part in relative.parts:
        destination = destination / part
        if destination.is_symlink():
            raise ValueError(f"Symlink in sync path: {destination}")
    # Also check platform-specific path interpretation (including Windows).
    if not destination.resolve().is_relative_to(root):
        raise ValueError(f"Sync path escapes local directory: {entry_path!r}")
    return destination


def _validate_entries(entries):
    if not isinstance(entries, list):
        raise ValueError("Invalid sync checkpoint: entries must be a list")
    try:
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("entry_type") not in ("document", "folder"):
                raise ValueError("invalid entry")
            remote_path(entry["entry_path"])
            if entry["entry_type"] == "document":
                datetime.strptime(entry["modified_date"], "%Y-%m-%dT%H:%M:%SZ")
        json.dumps(entries, allow_nan=False)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid sync checkpoint entries") from exc
    return entries


class _DataOnlyUnpickler(pickle.Unpickler):
    """Migrate legacy lists/dicts without importing or invoking Python globals."""

    def find_class(self, module, name):
        raise pickle.UnpicklingError("Globals are forbidden in sync checkpoints")

    def persistent_load(self, pid):
        raise pickle.UnpicklingError("Persistent references are forbidden")


def load_checkpoint(folder):
    checkpoint = Path(folder) / ".sync"
    if checkpoint.is_symlink():
        raise ValueError("Symlink used as sync checkpoint")
    if not checkpoint.exists():
        return []
    content = checkpoint.read_bytes()
    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        try:
            # Reject callable/object opcodes, including cached EXT references
            # which can bypass Unpickler.find_class(). Only plain data is needed.
            forbidden = {"GLOBAL", "STACK_GLOBAL", "REDUCE", "BUILD", "INST", "OBJ",
                         "NEWOBJ", "NEWOBJ_EX", "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID"}
            if any(opcode.name in forbidden for opcode, _, _ in pickletools.genops(content)):
                raise pickle.UnpicklingError("Only plain data is allowed")
            stream = io.BytesIO(content)
            entries = _DataOnlyUnpickler(stream).load()
            if stream.read():
                raise ValueError("Trailing data")
            _validate_entries(entries)
        except (pickle.UnpicklingError, EOFError, ValueError, TypeError, OverflowError) as exc:
            raise ValueError("Invalid or unsafe legacy sync checkpoint") from exc
        save_checkpoint(folder, entries)
        return entries
    if (not isinstance(payload, dict) or type(payload.get("version")) is not int
            or payload["version"] != 1):
        raise ValueError("Unsupported sync checkpoint format")
    return _validate_entries(payload.get("entries"))


def save_checkpoint(folder, entries):
    payload = {"version": 1, "entries": _validate_entries(entries)}
    checkpoint = Path(folder) / ".sync"
    if checkpoint.is_symlink():
        raise ValueError("Symlink used as sync checkpoint")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=folder,
                                         prefix=".sync-", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            json.dump(payload, output, ensure_ascii=False, allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, checkpoint)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
