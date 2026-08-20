from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from quant_hub.archive.contracts import ActorInput, Slug, TopicId


ResearchId = Annotated[str, StringConstraints(pattern=r"^res_[0-9a-f]{32}$")]
ResearchReleaseId = Annotated[str, StringConstraints(pattern=r"^rel_[0-9a-f]{32}$")]
CompletionDecisionId = Annotated[str, StringConstraints(pattern=r"^dec_[0-9a-f]{32}$")]
ResearchNodeId = Annotated[str, StringConstraints(pattern=r"^rnode_[0-9a-f]{32}$")]


class ApiError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    details: dict[str, Any] | list[Any] | None = None


class ApiEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_version: Literal["v1"] = "v1"
    data: dict[str, Any] | None = None
    error: ApiError | None = None
    meta: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def success_and_error_are_exclusive(self) -> "ApiEnvelope":
        if (self.data is None) == (self.error is None):
            raise ValueError("envelope must contain exactly one of data or error")
        return self


class CommentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    content: str = Field(min_length=1, max_length=8_000)


class CommentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    content: str = Field(min_length=1, max_length=8_000)


class ResearchTreeSync(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResearchProjectCreate(BaseModel):
    """Create a new top-level, file-backed research project."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=8_000)
    research_question: str | None = Field(default=None, max_length=8_000)
    research_content: str | None = Field(default=None, max_length=20_000)
    lifecycle_status: Literal[
        "todo", "in_progress", "review", "completed", "archived", "cancelled"
    ] = "todo"
    status_note: str | None = Field(default=None, max_length=4_000)


class ResearchNodeUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    title: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, max_length=8_000)
    research_question: str | None = Field(default=None, max_length=8_000)
    research_content: str | None = Field(default=None, max_length=20_000)
    lifecycle_status: Literal[
        "todo", "in_progress", "review", "completed", "archived", "cancelled"
    ] | None = None
    status_note: str | None = Field(default=None, max_length=4_000)

    @model_validator(mode="after")
    def require_workspace_change(self) -> Self:
        if not (self.model_fields_set - {"actor"}):
            raise ValueError("research node update requires at least one editable field")
        return self


class ResearchNodeCommentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    content: str = Field(min_length=1, max_length=8_000)


class ResearchNodeCommentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    content: str = Field(min_length=1, max_length=8_000)


class ResearchNodeCommentDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: ActorInput


class ResearchUpdateAnnotationCreate(BaseModel):
    """研究更新事实的追加说明；空说明仍可记录责任人。"""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    note: str | None = Field(default=None, max_length=500)


class TopicCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    topic_key: Slug
    title: str = Field(min_length=1, max_length=300)
    manual_order: int = Field(default=100, ge=0, le=1_000_000)


class ManualTopicCreate(BaseModel):
    """Dashboard 人工议题的 HTTP 创建契约。"""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    title: str = Field(min_length=1, max_length=300)
    state: Literal["planned", "paused"]
    note: str | None = Field(default=None, min_length=1, max_length=2_000)
    parent_topic_id: TopicId | None = None
    manual_order: int = Field(default=100, ge=0, le=1_000_000)


class ManualTopicUpdate(BaseModel):
    """Dashboard 人工议题的 HTTP 部分更新契约。"""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    title: str | None = Field(default=None, min_length=1, max_length=300)
    state: Literal["planned", "paused"] | None = None
    note: str | None = Field(default=None, min_length=1, max_length=2_000)
    parent_topic_id: TopicId | None = None
    manual_order: int | None = Field(default=None, ge=0, le=1_000_000)

    @model_validator(mode="after")
    def require_explicit_change(self) -> Self:
        if not (self.model_fields_set - {"actor"}):
            raise ValueError("manual topic update requires at least one editable field")
        return self


class ManualTopicDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: ActorInput


class TopicResearchLinkCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    research_id: ResearchId
    link_kind: Literal["primary", "supporting"]
    dashboard_primary: bool = False
    display_rank: int = Field(default=100, ge=0, le=1_000_000)
    provenance_urn: str = Field(min_length=3, max_length=512)

    @model_validator(mode="after")
    def dashboard_primary_requires_primary_link(self) -> Self:
        if self.dashboard_primary and self.link_kind != "primary":
            raise ValueError("dashboard primary must be a primary research link")
        return self


class TopicStateEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    state: Literal["planned", "paused"]
    note: str | None = Field(default=None, min_length=1, max_length=2_000)


class ResearchWorkStateEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: ActorInput
    state: Literal["planned", "in_progress", "paused"]
    note: str | None = Field(default=None, min_length=1, max_length=2_000)


class ResearchCompletionDecisionCreate(BaseModel):
    """受控 completion/revocation command；decision kind 由 authority 推导。"""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    decision: Literal["completed", "revoked"]
    research_release_id: ResearchReleaseId | None = None
    target_decision_id: CompletionDecisionId | None = None
    reason: str = Field(min_length=1, max_length=2_000)
    actor: ActorInput | None = None
    review_urn: str | None = Field(default=None, min_length=3, max_length=512)

    @model_validator(mode="after")
    def validate_controlled_decision(self) -> Self:
        if (self.actor is None) == (self.review_urn is None):
            raise ValueError(
                "completion decision requires exactly one human actor or independent review URN"
            )
        if self.decision == "completed":
            if self.research_release_id is None or self.target_decision_id is not None:
                raise ValueError(
                    "completed decision requires research_release_id and no target_decision_id"
                )
        elif self.target_decision_id is None or self.research_release_id is not None:
            raise ValueError(
                "revoked decision requires target_decision_id and no research_release_id"
            )
        return self
