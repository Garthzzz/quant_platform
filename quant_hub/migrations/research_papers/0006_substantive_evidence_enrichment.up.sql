CREATE TABLE evidence_substantive_enrichment (
    paper_id TEXT PRIMARY KEY REFERENCES paper(paper_id) ON DELETE RESTRICT,
    institutions_json TEXT NOT NULL CHECK(
        json_valid(institutions_json)
        AND json_type(institutions_json)='array'
        AND json_array_length(institutions_json) > 0
    ),
    institution_source_json TEXT NOT NULL CHECK(
        json_valid(institution_source_json)
        AND json_type(institution_source_json)='object'
    ),
    abstract_text TEXT CHECK(abstract_text IS NULL OR length(trim(abstract_text)) > 80),
    abstract_sha256 TEXT CHECK(
        abstract_sha256 IS NULL OR (
            length(abstract_sha256)=64
            AND abstract_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    abstract_source_json TEXT CHECK(
        abstract_source_json IS NULL OR (
            json_valid(abstract_source_json)
            AND json_type(abstract_source_json)='object'
        )
    ),
    abstract_translation_zh TEXT CHECK(
        abstract_translation_zh IS NULL OR length(trim(abstract_translation_zh)) > 40
    ),
    synthesis_zh TEXT CHECK(
        synthesis_zh IS NULL OR length(trim(synthesis_zh)) > 30
    ),
    core_conclusion_text TEXT CHECK(
        core_conclusion_text IS NULL OR length(trim(core_conclusion_text)) > 40
    ),
    core_conclusion_source_json TEXT CHECK(
        core_conclusion_source_json IS NULL OR (
            json_valid(core_conclusion_source_json)
            AND json_type(core_conclusion_source_json)='object'
        )
    ),
    local_pdf_relative_path TEXT CHECK(
        local_pdf_relative_path IS NULL OR (
            length(trim(local_pdf_relative_path)) > 0
            AND substr(local_pdf_relative_path,1,1) <> '/'
            AND instr(local_pdf_relative_path,'\\')=0
            AND instr(local_pdf_relative_path,'..')=0
            AND instr(local_pdf_relative_path,':')=0
        )
    ),
    local_pdf_sha256 TEXT CHECK(
        local_pdf_sha256 IS NULL OR (
            length(local_pdf_sha256)=64
            AND local_pdf_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    local_pdf_bytes INTEGER CHECK(local_pdf_bytes IS NULL OR local_pdf_bytes >= 10000),
    local_pdf_source_url TEXT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    reviewed_at TEXT NOT NULL CHECK(length(trim(reviewed_at)) > 0),
    CHECK(
        (abstract_text IS NULL AND abstract_sha256 IS NULL
         AND abstract_source_json IS NULL AND abstract_translation_zh IS NULL
         AND synthesis_zh IS NULL AND core_conclusion_text IS NULL
         AND core_conclusion_source_json IS NULL)
        OR
        (abstract_text IS NOT NULL AND abstract_sha256 IS NOT NULL
         AND abstract_source_json IS NOT NULL AND abstract_translation_zh IS NOT NULL
         AND synthesis_zh IS NOT NULL AND core_conclusion_text IS NOT NULL
         AND core_conclusion_source_json IS NOT NULL)
    ),
    CHECK(
        (local_pdf_relative_path IS NULL AND local_pdf_sha256 IS NULL
         AND local_pdf_bytes IS NULL)
        OR
        (local_pdf_relative_path IS NOT NULL AND local_pdf_sha256 IS NOT NULL
         AND local_pdf_bytes IS NOT NULL)
    )
) STRICT;

CREATE INDEX evidence_substantive_enrichment_pdf_sha256_idx
ON evidence_substantive_enrichment(local_pdf_sha256)
WHERE local_pdf_sha256 IS NOT NULL;
