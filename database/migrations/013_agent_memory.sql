DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'memory_type') THEN
    CREATE TYPE public.memory_type AS ENUM (
      'episodic',    -- specific past experience
      'semantic',    -- learned fact / rule
      'procedural',  -- how-to / workflow
      'reflection'   -- meta-cognition about past behavior
    );
  END IF;
END$$;

COMMENT ON TYPE public.memory_type IS
  'Category of agent memory.';


CREATE TABLE IF NOT EXISTS public.agent_memory (
  id                UUID                 PRIMARY KEY
                                         DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope
  organization_id   UUID                 NOT NULL
                                         REFERENCES public.organizations(id)
                                         ON DELETE CASCADE,

  -- Memory is scoped per-agent (the Triage Agent's memories are separate from Hunt's)
  agent_id          UUID                 NOT NULL
                                         REFERENCES public.agents(id)
                                         ON DELETE CASCADE,

  -- Denormalized for cheap filters
  agent_key         public.agent_key     NOT NULL,

  -- Human-friendly short reference (e.g., "MEM-A3F2B9")
  short_id          TEXT                 NOT NULL
                                         DEFAULT public.generate_short_id('MEM'),

  -- Classification
  memory_type       public.memory_type   NOT NULL,

  -- The memorable text (what gets recalled into a future prompt)
  content           TEXT                 NOT NULL,

  -- 384-dimensional semantic embedding (cosine similarity space)
  -- NULL allowed at insert time so we can write the row first,
  -- then update the embedding once it's computed asynchronously.
  embedding         extensions.vector(384),

  -- Where this memory came from
  source_type       TEXT,                              -- "event" | "threat" | "incident" | "run" | "manual" | "reflection"
  source_id         UUID,                              -- polymorphic FK

  -- Importance scoring (used for memory consolidation / forgetting)
  -- 0   = trivial, can forget anytime
  -- 100 = core knowledge, never forget
  importance        SMALLINT             NOT NULL DEFAULT 50,

  -- Recall tracking
  access_count      INTEGER              NOT NULL DEFAULT 0,
  last_accessed_at  TIMESTAMPTZ,

  -- Composite decay score: importance × recency × frequency
  -- Higher = more likely to be retained when pruning. Refreshed by triggers.
  decay_score       NUMERIC(8,4)         NOT NULL DEFAULT 0,

  -- Free-form context
  metadata          JSONB                NOT NULL DEFAULT '{}'::jsonb,

  -- Free-form labels
  tags              TEXT[]               NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Optional expiration (e.g., ephemeral working-memory entries)
  expires_at        TIMESTAMPTZ,

  -- Standard timestamps
  created_at        TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ          NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT agent_memory_content_length
    CHECK (char_length(content) BETWEEN 1 AND 8000),
  CONSTRAINT agent_memory_importance_range
    CHECK (importance BETWEEN 0 AND 100),
  CONSTRAINT agent_memory_access_count_nonneg
    CHECK (access_count >= 0),
  CONSTRAINT agent_memory_decay_score_nonneg
    CHECK (decay_score >= 0)
);

COMMENT ON TABLE  public.agent_memory                  IS 'Semantic memory store for AI agents, backed by pgvector.';
COMMENT ON COLUMN public.agent_memory.id               IS 'UUID primary key.';
COMMENT ON COLUMN public.agent_memory.organization_id  IS 'Owning organization.';
COMMENT ON COLUMN public.agent_memory.agent_id         IS 'Agent whose memory this is.';
COMMENT ON COLUMN public.agent_memory.agent_key        IS 'Denormalized agent type for cheap filters.';
COMMENT ON COLUMN public.agent_memory.short_id         IS 'Human-friendly short reference.';
COMMENT ON COLUMN public.agent_memory.memory_type      IS 'Category: episodic, semantic, procedural, reflection.';
COMMENT ON COLUMN public.agent_memory.content          IS 'The memorable text (recalled into future prompts).';
COMMENT ON COLUMN public.agent_memory.embedding        IS '384-dim semantic embedding vector (cosine space).';
COMMENT ON COLUMN public.agent_memory.source_type      IS 'What kind of entity this memory came from.';
COMMENT ON COLUMN public.agent_memory.source_id        IS 'UUID of the source entity (polymorphic).';
COMMENT ON COLUMN public.agent_memory.importance       IS 'Retention priority (0=trivial, 100=core).';
COMMENT ON COLUMN public.agent_memory.access_count     IS 'Number of times this memory has been recalled.';
COMMENT ON COLUMN public.agent_memory.last_accessed_at IS 'Most recent recall timestamp.';
COMMENT ON COLUMN public.agent_memory.decay_score      IS 'Composite retention score: importance × recency × frequency.';
COMMENT ON COLUMN public.agent_memory.metadata         IS 'Free-form additional context.';
COMMENT ON COLUMN public.agent_memory.tags             IS 'Free-form labels.';
COMMENT ON COLUMN public.agent_memory.expires_at       IS 'Optional TTL (NULL = never expires).';


-- Per-agent recent memories
CREATE INDEX IF NOT EXISTS idx_agent_memory_agent_id
  ON public.agent_memory(agent_id, created_at DESC);

-- Org-scoped listing
CREATE INDEX IF NOT EXISTS idx_agent_memory_org
  ON public.agent_memory(organization_id, created_at DESC);

-- Memory type filtering
CREATE INDEX IF NOT EXISTS idx_agent_memory_type
  ON public.agent_memory(agent_id, memory_type, created_at DESC);

-- Source lookups (find all memories from one event/threat/incident)
CREATE INDEX IF NOT EXISTS idx_agent_memory_source
  ON public.agent_memory(source_type, source_id)
  WHERE source_id IS NOT NULL;

-- Importance-ranked retrieval
CREATE INDEX IF NOT EXISTS idx_agent_memory_importance
  ON public.agent_memory(agent_id, importance DESC, decay_score DESC);

-- Expiration scan (prune expired memories)
CREATE INDEX IF NOT EXISTS idx_agent_memory_expires_at
  ON public.agent_memory(expires_at)
  WHERE expires_at IS NOT NULL;

-- Short-ID lookup
CREATE INDEX IF NOT EXISTS idx_agent_memory_short_id
  ON public.agent_memory(short_id);

-- Tag search
CREATE INDEX IF NOT EXISTS idx_agent_memory_tags
  ON public.agent_memory USING GIN(tags);

-- HNSW (Hierarchical Navigable Small World) gives sub-linear
-- nearest-neighbor search even at millions of rows. We index
-- using cosine distance (vector_cosine_ops).
--
-- m            — connections per node (default 16). Higher = better recall, more memory.
-- ef_construction — build-time search width (default 64). Higher = better quality, slower build.

CREATE INDEX IF NOT EXISTS idx_agent_memory_embedding_hnsw
  ON public.agent_memory
  USING hnsw (embedding extensions.vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);


DROP TRIGGER IF EXISTS set_agent_memory_updated_at ON public.agent_memory;

CREATE TRIGGER set_agent_memory_updated_at
  BEFORE UPDATE ON public.agent_memory
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();

-- Given a query embedding, return the top-K most similar memories
-- for the given agent. Returned in similarity-descending order.
--
-- similarity = 1 - cosine_distance, so 1.0 = identical, 0.0 = orthogonal.
--
-- Example call:
--   SELECT * FROM public.search_agent_memory(
--     p_agent_id        := '<uuid>',
--     p_query_embedding := '[0.12, -0.41, ...]'::vector,
--     p_limit           := 5,
--     p_min_similarity  := 0.5
--   );

CREATE OR REPLACE FUNCTION public.search_agent_memory(
  p_agent_id         UUID,
  p_query_embedding  extensions.vector(384),
  p_limit            INTEGER = 5,
  p_min_similarity   NUMERIC = 0.0,
  p_memory_type      public.memory_type = NULL
)
RETURNS TABLE (
  id            UUID,
  short_id      TEXT,
  memory_type   public.memory_type,
  content       TEXT,
  importance    SMALLINT,
  similarity    NUMERIC,
  source_type   TEXT,
  source_id     UUID,
  created_at    TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
  RETURN QUERY
  SELECT
    m.id,
    m.short_id,
    m.memory_type,
    m.content,
    m.importance,
    (1 - (m.embedding <=> p_query_embedding))::NUMERIC AS similarity,
    m.source_type,
    m.source_id,
    m.created_at
  FROM public.agent_memory m
  WHERE m.agent_id = p_agent_id
    AND m.embedding IS NOT NULL
    AND (p_memory_type IS NULL OR m.memory_type = p_memory_type)
    AND (m.expires_at IS NULL OR m.expires_at > NOW())
    AND (1 - (m.embedding <=> p_query_embedding))::NUMERIC >= p_min_similarity
  ORDER BY m.embedding <=> p_query_embedding ASC
  LIMIT p_limit;
END;
$$;

COMMENT ON FUNCTION public.search_agent_memory IS
  'Top-K cosine-similarity search over an agent''s memories.';

-- When the application increments access_count to record a recall,
-- recompute the decay score so importance + recency + frequency
-- all factor into retention.
--
-- Decay formula:
--   recency_factor   = exp(-age_days / 30)                 (decays over ~30 days)
--   frequency_factor = log(1 + access_count)
--   decay_score      = importance * (0.5 + 0.3*recency + 0.2*frequency_factor / 10)

CREATE OR REPLACE FUNCTION public.recompute_memory_decay_score()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  age_days         NUMERIC;
  recency_factor   NUMERIC;
  frequency_factor NUMERIC;
BEGIN
  age_days         := EXTRACT(EPOCH FROM (NOW() - NEW.created_at)) / 86400.0;
  recency_factor   := exp(-age_days / 30.0);
  frequency_factor := ln(1 + GREATEST(NEW.access_count, 0));

  NEW.decay_score := GREATEST(
    0,
    LEAST(
      9999.9999,
      NEW.importance * (0.5 + 0.3 * recency_factor + 0.02 * frequency_factor)
    )
  );

  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.recompute_memory_decay_score() IS
  'Recomputes decay_score from importance, recency, and access frequency.';

DROP TRIGGER IF EXISTS recompute_memory_decay ON public.agent_memory;

CREATE TRIGGER recompute_memory_decay
  BEFORE INSERT OR UPDATE OF importance, access_count, last_accessed_at
  ON public.agent_memory
  FOR EACH ROW
  EXECUTE FUNCTION public.recompute_memory_decay_score();


ALTER TABLE public.agent_memory ENABLE ROW LEVEL SECURITY;
