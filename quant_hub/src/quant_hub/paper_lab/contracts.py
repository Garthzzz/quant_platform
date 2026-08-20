"""Paper Lab 写入契约的单一事实源。"""

from __future__ import annotations


EDITABLE_PAPER_FIELDS = (
    "title", "link", "authors", "venue", "institution", "model_type",
    "asset_market", "start_year", "end_year", "study_period", "sample_length",
    "prediction_target", "input_features", "feature_count", "oos_method", "metrics",
    "performance", "special_tech", "source_type", "research_topic", "main_findings",
    "innovations_insights", "caveats_replication", "summary", "rating", "data_input",
    "data_preprocess", "method_model", "method_special", "loss_function",
    "training_config", "pipeline_output", "diagram", "status", "phase",
)


__all__ = ["EDITABLE_PAPER_FIELDS"]
