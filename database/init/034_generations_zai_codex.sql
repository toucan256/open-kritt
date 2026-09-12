-- Allow Z.ai GLM Coding Plan generations through the Codex harness.

ALTER TABLE public.generations
    DROP CONSTRAINT IF EXISTS generations_model_provider_check;

ALTER TABLE public.generations
    ADD CONSTRAINT generations_model_provider_check
    CHECK (model_provider IN ('codex', 'claude', 'openrouter', 'xai', 'zai'));

ALTER TABLE public.generations
    DROP CONSTRAINT IF EXISTS generations_check;

ALTER TABLE public.generations
    ADD CONSTRAINT generations_check
    CHECK (
        (model_provider = 'codex' AND harness = 'codex') OR
        (model_provider = 'claude' AND harness = 'claude-code') OR
        model_provider = 'openrouter' OR
        (model_provider = 'xai' AND harness = 'grok-build') OR
        (model_provider = 'zai' AND harness = 'codex')
    );
