import { describe, it, expect } from 'vitest';
import { listFindings, getFinding, updateFinding, listComponents, exportSbom } from './index.js';

describe('fake API', () => {
  it('lists findings in contract shape and honours filters', async () => {
    const all = await listFindings('r', { status: 'all' });
    expect(all.total).toBe(12);
    expect(all.items[0]).toHaveProperty('vulnId');
    const open = await listFindings('r');
    expect(open.total).toBe(11);
    const crit = await listFindings('r', { severity: 'critical' });
    expect(crit.items.every((f) => f.severity === 'critical')).toBe(true);
    expect(crit.counts.high).toBeGreaterThan(0); // counts ignore the severity filter
  });

  it('returns details incl. unknown, upstream-error CVE, and rejects bad input', async () => {
    const all = await listFindings('r', { status: 'all', limit: 100 });
    const details = await Promise.all(all.items.map((i) => getFinding(i.id)));
    expect(details.some((d) => d.severity === 'unknown' && d.scoreSource === null)).toBe(true);
    expect(details.some((d) => d.cves.some((c) => c.error === 'UPSTREAM_UNAVAILABLE'))).toBe(true);
    await expect(getFinding('nope')).rejects.toMatchObject({ status: 404, code: 'NOT_FOUND' });
    await expect(updateFinding(details[0].id, { status: 'ignored', reason: 'x' })).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
  });

  it('ignores and re-opens, updating component vulnerability counts', async () => {
    const before = await listComponents('r', { q: 'qs' });
    expect(before.items[0].vulnerabilityCount).toBe(1);
    const all = await listFindings('r', { q: 'GHSA-hrpp-h998-j3pp' });
    const id = all.items[0].id;
    const ignored = await updateFinding(id, { status: 'ignored', reason: 'demo reason' });
    expect(ignored.ignore.reason).toBe('demo reason');
    expect((await listComponents('r', { q: 'qs' })).items[0].vulnerabilityCount).toBe(0);
    expect((await updateFinding(id, { status: 'open' })).ignore).toBeNull();
  });

  it('has ~40 components and exports valid-looking CycloneDX', async () => {
    const c = await listComponents('r', { limit: 200 });
    expect(c.summary.total).toBe(40);
    const { blob, filename } = await exportSbom();
    const doc = JSON.parse(await blob.text());
    expect(doc).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.5' });
    expect(doc.components).toHaveLength(40);
    expect(filename).toMatch(/\.cdx\.json$/);
  });
});
