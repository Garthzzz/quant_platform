from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import tempfile

from quant_hub.config import (
    ConfigurationError,
    ensure_no_reparse_components,
    is_reparse_point,
    stat_is_reparse_point,
)
from quant_hub.ids import object_id_for_sha256, sha256_hex, validate_object_id


class ObjectStoreError(RuntimeError):
    pass


class ObjectCorruptionError(ObjectStoreError):
    pass


@dataclass(frozen=True, slots=True)
class StoredObject:
    object_id: str
    sha256: str
    bytes: int
    relative_path: str
    created: bool


class ObjectStore:
    def __init__(self, root: Path):
        self.root = root.absolute()

    def _ensure_root(self) -> None:
        try:
            ensure_no_reparse_components(self.root)
            self.root.mkdir(parents=True, exist_ok=True)
            ensure_no_reparse_components(self.root)
        except ConfigurationError as error:
            raise ObjectStoreError("object root contains a reparse component") from error
        except OSError as error:
            raise ObjectStoreError("object root cannot be created") from error
        info = self.root.lstat()
        if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
            raise ObjectStoreError("object root must be a real directory")

    @staticmethod
    def relative_path(digest: str) -> Path:
        return Path(digest[:2]) / digest[2:4] / f"{digest}.blob"

    def _verify_existing(self, path: Path, digest: str, size: int | None) -> bytes:
        try:
            info = path.lstat()
        except FileNotFoundError as error:
            raise ObjectCorruptionError(f"content object is missing: {digest}") from error
        if stat_is_reparse_point(info) or not stat.S_ISREG(info.st_mode):
            raise ObjectCorruptionError("object path is not a regular non-reparse file")
        try:
            payload = path.read_bytes()
        except FileNotFoundError as error:
            raise ObjectCorruptionError(f"content object disappeared: {digest}") from error
        if (size is not None and len(payload) != size) or sha256_hex(payload) != digest:
            raise ObjectCorruptionError(f"existing object bytes do not match identity: {digest}")
        return payload

    @staticmethod
    def _ensure_directory_component(path: Path) -> None:
        try:
            ensure_no_reparse_components(path)
            path.mkdir(exist_ok=True)
            ensure_no_reparse_components(path)
            info = path.lstat()
        except ConfigurationError as error:
            raise ObjectStoreError("object path contains a reparse component") from error
        except OSError as error:
            raise ObjectStoreError("object shard directory cannot be created") from error
        if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
            raise ObjectStoreError("object path contains a reparse or non-directory component")

    def put_bytes(self, payload: bytes) -> StoredObject:
        self._ensure_root()
        digest = sha256_hex(payload)
        relative = self.relative_path(digest)
        prefix = self.root / relative.parts[0]
        parent = self.root / relative.parent
        self._ensure_directory_component(prefix)
        self._ensure_directory_component(parent)
        target = self.root / relative
        if os.path.lexists(target):
            self._verify_existing(target, digest, len(payload))
            return StoredObject(
                object_id_for_sha256(digest), digest, len(payload), relative.as_posix(), False
            )

        descriptor, temporary_name = tempfile.mkstemp(prefix=".qrh-object-", dir=parent)
        temporary = Path(temporary_name)
        created = False
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if sha256_hex(temporary.read_bytes()) != digest:
                raise ObjectStoreError("temporary object verification failed")
            try:
                os.link(temporary, target)
                created = True
            except FileExistsError:
                self._verify_existing(target, digest, len(payload))
            except OSError as error:
                if os.path.lexists(target):
                    self._verify_existing(target, digest, len(payload))
                else:
                    raise ObjectStoreError("atomic object finalize failed") from error
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        self._verify_existing(target, digest, len(payload))
        return StoredObject(
            object_id_for_sha256(digest), digest, len(payload), relative.as_posix(), created
        )

    def read_bytes(self, object_id: str) -> bytes:
        validate_object_id(object_id)
        self._ensure_root()
        prefix = "obj_sha256_"
        digest = object_id[len(prefix) :]
        relative = self.relative_path(digest)
        target = self.root / relative
        for candidate in (self.root / relative.parts[0], target.parent):
            if not os.path.lexists(candidate):
                raise ObjectCorruptionError(f"content object is missing: {object_id}")
            if is_reparse_point(candidate) or not candidate.is_dir():
                raise ObjectCorruptionError("object read path contains a reparse component")
        if not os.path.lexists(target):
            raise ObjectCorruptionError(f"content object is missing: {object_id}")
        return self._verify_existing(target, digest, None)
