"""PEP 517 backend that forbids stale setuptools build-tree inheritance."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
from typing import Mapping, Sequence

from setuptools import build_meta as _setuptools


class UnsafeBuildCache(RuntimeError):
    """The local build cache cannot be proven to be an ordinary child tree."""


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _clean_exact_build_cache() -> None:
    project = Path(__file__).resolve(strict=True).parent
    candidate = project / "build"
    if not os.path.lexists(candidate):
        return
    info = candidate.lstat()
    if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise UnsafeBuildCache("quant_hub/build is not an ordinary directory")
    resolved = candidate.resolve(strict=True)
    if resolved.parent != project or resolved.name != "build":
        raise UnsafeBuildCache("quant_hub/build resolves outside the project")
    shutil.rmtree(resolved)
    if os.path.lexists(candidate):
        raise UnsafeBuildCache("quant_hub/build cleanup did not complete")


def build_wheel(
    wheel_directory: str,
    config_settings: Mapping[str, object] | None = None,
    metadata_directory: str | None = None,
) -> str:
    _clean_exact_build_cache()
    return _setuptools.build_wheel(
        wheel_directory, config_settings, metadata_directory
    )


def build_sdist(
    sdist_directory: str,
    config_settings: Mapping[str, object] | None = None,
) -> str:
    _clean_exact_build_cache()
    return _setuptools.build_sdist(sdist_directory, config_settings)


def build_editable(
    wheel_directory: str,
    config_settings: Mapping[str, object] | None = None,
    metadata_directory: str | None = None,
) -> str:
    _clean_exact_build_cache()
    return _setuptools.build_editable(
        wheel_directory, config_settings, metadata_directory
    )


get_requires_for_build_wheel = _setuptools.get_requires_for_build_wheel
get_requires_for_build_sdist = _setuptools.get_requires_for_build_sdist
get_requires_for_build_editable = _setuptools.get_requires_for_build_editable
prepare_metadata_for_build_wheel = _setuptools.prepare_metadata_for_build_wheel
prepare_metadata_for_build_editable = _setuptools.prepare_metadata_for_build_editable


__all__: Sequence[str] = (
    "build_editable",
    "build_sdist",
    "build_wheel",
    "get_requires_for_build_editable",
    "get_requires_for_build_sdist",
    "get_requires_for_build_wheel",
    "prepare_metadata_for_build_editable",
    "prepare_metadata_for_build_wheel",
)
