import { createHash } from 'node:crypto';
import { Router } from 'express';
import { prisma } from '../db.js';
import { serializeVulnerability } from '../lib/serialize.js';

const router = Router();

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return pythonJsonScalar(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${pythonJsonScalar(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`;
}

function pythonJsonScalar(value) {
  const serialized = JSON.stringify(value);
  if (typeof value !== 'string') return serialized;
  return serialized.replace(/[\u007f-\uffff]/g, (character) => {
    return `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`;
  });
}

export function canonicalJsonSha256(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

function parseExpectedIdentity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const expectedKeys = new Set(['scanId', 'workflowId', 'repository', 'revisionLabel', 'candidateCanonicalSha256']);
  if (Object.keys(value).length !== expectedKeys.size || Object.keys(value).some((key) => !expectedKeys.has(key))) {
    return null;
  }
  if (![value.scanId, value.workflowId].every((item) => /^[1-9][0-9]*$/.test(item))) return null;
  if (![value.repository, value.revisionLabel].every((item) => typeof item === 'string' && item.length > 0))
    return null;
  if (!/^[0-9a-f]{64}$/.test(value.candidateCanonicalSha256)) return null;
  return value;
}

export function matchesExpectedIdentity(vulnerability, scan, expectedIdentity) {
  return (
    vulnerability.scanId.toString() === expectedIdentity.scanId &&
    vulnerability.workflowId.toString() === expectedIdentity.workflowId &&
    scan.id.toString() === expectedIdentity.scanId &&
    scan.workflowId.toString() === expectedIdentity.workflowId &&
    scan.repoFull === expectedIdentity.repository &&
    scan.commitSha === expectedIdentity.revisionLabel &&
    canonicalJsonSha256(vulnerability.jsonAnswer) === expectedIdentity.candidateCanonicalSha256
  );
}

export function buildVulnerabilityPatch(body = {}) {
  const data = {};
  let appendComments;
  let expectedIdentity;
  if ('interesting' in body) {
    const val = body.interesting;
    if (val === null) data.interesting = null;
    else if (val === 0 || val === 1 || val === '0' || val === '1') data.interesting = BigInt(Number(val));
    else return { error: { field: 'interesting', message: 'interesting must be 0, 1, or null.' } };
  }
  if ('comments' in body && 'appendComments' in body) {
    return { error: { field: 'comments', message: 'comments and appendComments are mutually exclusive.' } };
  }
  if ('comments' in body) {
    data.comments = body.comments === null || body.comments === '' ? null : String(body.comments);
  }
  if ('appendComments' in body) {
    if (typeof body.appendComments !== 'string' || !body.appendComments.trim()) {
      return { error: { field: 'appendComments', message: 'appendComments must be a non-empty string.' } };
    }
    if (Buffer.byteLength(body.appendComments, 'utf8') > 64 * 1024) {
      return { error: { field: 'appendComments', message: 'appendComments must not exceed 64 KiB.' } };
    }
    appendComments = body.appendComments;
    expectedIdentity = parseExpectedIdentity(body.expectedIdentity);
    if (!expectedIdentity) {
      return {
        error: {
          field: 'expectedIdentity',
          message: 'appendComments requires an exact scan and candidate identity.',
        },
      };
    }
  }
  if (Object.keys(data).length === 0 && appendComments === undefined) {
    return { error: { field: 'body', message: 'Provide interesting, comments, and/or appendComments.' } };
  }
  return { data, appendComments, expectedIdentity };
}

// GET /api/vulnerabilities/:id — a single finding with its post-script output.
router.get('/:id', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const v = await prisma.vulnerability.findUnique({ where: { id } });
    if (!v) return res.status(404).json({ error: 'Vulnerability not found.' });
    const [enrichments, duplicates] = await Promise.all([
      prisma.vulnerabilityEnrichment.findMany({ where: { vulnerabilityId: id }, orderBy: [{ id: 'asc' }] }),
      prisma.vulnerability.findMany({
        where: { scanId: v.scanId, dedupeCanonicalId: id, dedupeIsCanonical: false },
        select: { id: true },
        orderBy: [{ id: 'asc' }],
      }),
    ]);
    res.json(
      serializeVulnerability(v, {
        enrichments,
        duplicateIds: duplicates.map((d) => d.id),
      })
    );
  } catch (e) {
    next(e);
  }
});

// PATCH /api/vulnerabilities/:id — user review: interesting flag and/or comments.
// interesting: 1 (interesting), 0 (not interesting), or null (unmarked).
// appendComments: atomically append a non-empty marker once without overwriting concurrent comments.
router.patch('/:id', async (req, res, next) => {
  try {
    const id = BigInt(req.params.id);
    const existing = await prisma.vulnerability.findUnique({ where: { id }, select: { id: true } });
    if (!existing) return res.status(404).json({ error: 'Vulnerability not found.' });

    const patch = buildVulnerabilityPatch(req.body || {});
    if (patch.error) {
      return res.status(422).json({ errors: [patch.error] });
    }

    const updated = await prisma.$transaction(async (tx) => {
      if (patch.appendComments !== undefined) {
        const locked = await tx.$queryRaw`
          SELECT v."id"
          FROM "workflows"."vulnerabilities" v
          JOIN "public"."scans" s ON s."id" = v."scan_id"
          WHERE v."id" = ${id}
          FOR UPDATE OF v, s
        `;
        if (locked.length !== 1) return { identityConflict: true };
        const [vulnerability, scan] = await Promise.all([
          tx.vulnerability.findUnique({
            where: { id },
            select: { id: true, scanId: true, workflowId: true, jsonAnswer: true },
          }),
          tx.scan.findUnique({ where: { id: BigInt(patch.expectedIdentity.scanId) } }),
        ]);
        if (!vulnerability || !scan || !matchesExpectedIdentity(vulnerability, scan, patch.expectedIdentity)) {
          return { identityConflict: true };
        }
        await tx.$executeRaw`
          UPDATE "workflows"."vulnerabilities"
          SET
            "comments" = CASE
              WHEN "comments" IS NULL OR "comments" = '' THEN ${patch.appendComments}
              WHEN POSITION(${patch.appendComments} IN "comments") > 0 THEN "comments"
              ELSE "comments" || E'\n\n' || ${patch.appendComments}
            END,
            "updated_at" = NOW()
          WHERE "id" = ${id}
        `;
      }
      if (Object.keys(patch.data).length > 0) {
        return tx.vulnerability.update({
          where: { id },
          data: patch.data,
          select: { id: true, scanId: true, interesting: true, comments: true },
        });
      }
      return tx.vulnerability.findUnique({
        where: { id },
        select: { id: true, scanId: true, interesting: true, comments: true },
      });
    });
    if (updated.identityConflict) {
      return res.status(409).json({ error: 'Vulnerability identity changed; append rejected.' });
    }
    res.json({
      id: updated.id.toString(),
      scanId: updated.scanId.toString(),
      interesting:
        updated.interesting === null || updated.interesting === undefined ? null : Number(updated.interesting),
      comments: updated.comments ?? null,
    });
  } catch (e) {
    next(e);
  }
});

export default router;
