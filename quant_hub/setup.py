from __future__ import annotations

import os
import stat
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.errors import SetupError


_PRIVATE_PRESENTATION_JSON = (
    "archive_presentation.json",
    "citation_projection_overrides.json",
    "evidence_zh_overlays.json",
    "research_supplements.json",
)
_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _assert_plain_build_path(path: Path, *, root: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SetupError("generated package data cannot be inspected") from exc
    if path.is_symlink() or (
        getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    ):
        raise SetupError("generated package data contains a reparse point")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SetupError("generated package data cannot be resolved") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise SetupError("generated package data escapes the build root") from exc


def prune_private_presentation_data(build_lib: str | os.PathLike[str]) -> None:
    """Remove ignored business data from a generated package tree.

    ``build_py`` does not clean an existing build directory.  Without this
    final closed-path pass, stale package-data entries can survive a later
    public wheel build even after they have been excluded in ``pyproject``.
    """

    root_path = Path(os.path.abspath(build_lib))
    for ancestor in (*reversed(root_path.parents), root_path):
        try:
            ancestor_metadata = ancestor.lstat()
        except OSError as exc:
            raise SetupError("generated package root cannot be inspected") from exc
        if ancestor.is_symlink() or (
            getattr(ancestor_metadata, "st_file_attributes", 0)
            & _WINDOWS_REPARSE_POINT
        ):
            raise SetupError("generated package root contains a reparse point")
    try:
        root = root_path.resolve(strict=True)
    except OSError as exc:
        raise SetupError("generated package root cannot be resolved") from exc
    if not root.is_dir():
        raise SetupError("generated package root is not a directory")
    presentation = root / "quant_hub" / "presentation"
    if not os.path.lexists(presentation):
        return
    _assert_plain_build_path(presentation, root=root)

    for name in _PRIVATE_PRESENTATION_JSON:
        candidate = presentation / name
        if not os.path.lexists(candidate):
            continue
        _assert_plain_build_path(candidate, root=root)
        if not candidate.is_file():
            raise SetupError("generated private presentation path is not a file")
        candidate.unlink()

    supplements = presentation / "supplements"
    if not os.path.lexists(supplements):
        return
    _assert_plain_build_path(supplements, root=root)
    private_files: list[Path] = []
    for current, directories, files in os.walk(
        supplements, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        _assert_plain_build_path(current_path, root=root)
        for child in (*directories, *files):
            _assert_plain_build_path(current_path / child, root=root)
        for file_name in files:
            candidate = current_path / file_name
            if not candidate.is_file():
                raise SetupError("generated private presentation path is not a file")
            private_files.append(candidate)
    for candidate in private_files:
        candidate.unlink()


class PublicBuildPy(build_py):
    def run(self) -> None:
        super().run()
        prune_private_presentation_data(self.build_lib)


if __name__ == "__main__":
    setup(cmdclass={"build_py": PublicBuildPy})
