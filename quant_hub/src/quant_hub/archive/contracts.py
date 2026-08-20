from __future__ import annotations

import re
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .source_reader import validate_archive_relative_path


Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,95}$")]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
TopicId = Annotated[str, StringConstraints(pattern=r"^top_[0-9a-f]{32}$")]

DocumentRole = Literal[
    "primary",
    "chapter",
    "appendix",
    "historical",
    "slides",
    "poster",
    "supporting",
]
NavigationRole = Literal["primary", "section", "appendix", "supporting", "historical"]
VersionRelationKind = Literal[
    "supersedes",
    "derived_from",
    "exact_duplicate_alias",
    "translation_of",
    "unknown_possible_lineage",
]


class ArchiveDocumentInput(BaseModel):
    """经人工或审核确认的 source→document 映射，不从文件名猜身份。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    document_slug: Slug
    document_role: DocumentRole
    source_path: str
    approved_origin_uri: str = Field(pattern=r"^archive:///[^\s]+$", max_length=2_000)
    approved_object_urn: str = Field(
        pattern=r"^qrh:object:obj_sha256_[0-9a-f]{64}$", max_length=96
    )
    approved_content_sha256: Sha256
    approved_bytes: int = Field(ge=0)
    navigation_role: NavigationRole = "supporting"
    sort_key: int = Field(default=100, ge=0, le=1_000_000)
    mapping_authority_urn: str = Field(min_length=3, max_length=512)
    mapping_note: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def validate_source_identity(self) -> Self:
        validate_archive_relative_path(self.source_path)
        if not self.approved_object_urn.endswith(self.approved_content_sha256):
            raise ValueError("approved object URN must match approved content SHA-256")
        return self


class ArchiveVersionRelationInput(BaseModel):
    """显式、带来源的版本关系；方向固定为 from → to。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    document_slug: Slug
    from_content_sha256: Sha256
    to_content_sha256: Sha256
    relation_kind: VersionRelationKind
    status: Literal["proposed", "verified"]
    provenance_urn: str = Field(min_length=3, max_length=512)

    @model_validator(mode="after")
    def validate_distinct_versions(self) -> Self:
        if self.from_content_sha256 == self.to_content_sha256:
            raise ValueError("a lineage relation requires two different content versions")
        return self


class ArchiveReleaseInput(BaseModel):
    """一次不可变 research release 的完整显式输入。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    research_slug: Slug
    display_title: str = Field(min_length=1, max_length=300)
    release_key: Slug
    documents: tuple[ArchiveDocumentInput, ...] = Field(min_length=1)
    version_relations: tuple[ArchiveVersionRelationInput, ...] = ()
    summary: str | None = Field(default=None, min_length=1, max_length=1_000)
    summary_provenance_urn: str | None = Field(default=None, min_length=3, max_length=512)
    activate: bool = True
    release_snapshot_urn: str | None = Field(default=None, min_length=3, max_length=512)
    activation_decision_hash: Sha256 | None = None

    @model_validator(mode="after")
    def validate_release_contract(self) -> Self:
        slugs = [item.document_slug for item in self.documents]
        if len(slugs) != len(set(slugs)):
            raise ValueError("a release cannot contain two versions of the same document")
        sort_keys = [item.sort_key for item in self.documents]
        if len(sort_keys) != len(set(sort_keys)):
            raise ValueError("release document sort keys must be unique")
        primary_count = sum(item.navigation_role == "primary" for item in self.documents)
        if primary_count != 1:
            raise ValueError("a release must contain exactly one primary navigation document")
        document_slugs = set(slugs)
        if any(item.document_slug not in document_slugs for item in self.version_relations):
            raise ValueError("version relation must target a document in this release")
        if (self.summary is None) != (self.summary_provenance_urn is None):
            raise ValueError("summary and summary provenance must be supplied together")
        if self.summary_provenance_urn is not None and not re.fullmatch(
            r"qrh:object:obj_sha256_[0-9a-f]{64}", self.summary_provenance_urn
        ):
            raise ValueError(
                "summary provenance must resolve to a registered content object"
            )
        if self.activate and (
            self.release_snapshot_urn is None or self.activation_decision_hash is None
        ):
            raise ValueError("activation requires an authority URN and decision hash")
        if not self.activate and (
            self.release_snapshot_urn is not None
            or self.activation_decision_hash is not None
        ):
            raise ValueError("inactive release cannot carry an activation decision")
        return self


class ActorInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_kind: Literal["zhang_zhengze", "song_dingkun", "other"]
    display_name: str | None = Field(default=None, min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_actor(self) -> Self:
        preset = {
            "zhang_zhengze": "张正泽",
            "song_dingkun": "宋定坤",
        }
        if self.actor_kind in preset:
            if self.display_name not in (None, preset[self.actor_kind]):
                raise ValueError("preset actor display name is fixed")
        else:
            if self.display_name is None or not self.display_name.strip():
                raise ValueError("other actor requires a non-empty name")
            if self.display_name.strip() in preset.values():
                raise ValueError("other actor cannot impersonate a preset actor")
        return self


class TopicInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    topic_key: Slug
    title: str = Field(min_length=1, max_length=300)
    manual_order: int = Field(default=100, ge=0, le=1_000_000)


class ManualTopicCreateInput(BaseModel):
    """研究员在 Dashboard 中原子创建的人工研究议题。"""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    title: str = Field(min_length=1, max_length=300)
    state: Literal["planned", "paused"]
    note: str | None = Field(default=None, min_length=1, max_length=2_000)
    parent_topic_id: TopicId | None = None
    manual_order: int = Field(default=100, ge=0, le=1_000_000)


class ManualTopicUpdateInput(BaseModel):
    """人工研究议题的部分更新；显式 ``None`` 可清空说明或父级。"""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    title: str | None = Field(default=None, min_length=1, max_length=300)
    state: Literal["planned", "paused"] | None = None
    note: str | None = Field(default=None, min_length=1, max_length=2_000)
    parent_topic_id: TopicId | None = None
    manual_order: int | None = Field(default=None, ge=0, le=1_000_000)

    @model_validator(mode="after")
    def require_explicit_change(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("manual topic update requires at least one field")
        return self
