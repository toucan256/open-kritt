-- Engine-observed digest binding for local repository scans.
-- The request expectation remains in scans.configuration.source_attestation;
-- this column is null until an engine workspace independently verifies the
-- pinned snapshot and records the observation before starting a harness.

ALTER TABLE public.scans
    ADD COLUMN IF NOT EXISTS source_attestation jsonb;
