import { describe, it, expect } from 'vitest';
import { parseCvssVector } from './cvss.js';

describe('parseCvssVector', () => {
  it('parses a CVSS 3.1 vector into readable metrics', () => {
    const r = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H');
    expect(r.version).toBe('3.1');
    expect(r.metrics).toHaveLength(8);
    expect(r.metrics[0]).toEqual({ key: 'AV', label: 'Attack vector', value: 'N', text: 'Network' });
    expect(r.metrics.find((m) => m.key === 'A').text).toBe('High');
    expect(r.metrics.find((m) => m.key === 'S').text).toBe('Unchanged');
  });

  it('parses CVSS 4.0 and legacy 2.0 vectors', () => {
    const v4 = parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(v4.version).toBe('4.0');
    expect(v4.metrics.find((m) => m.key === 'AT').text).toBe('None');
    const v2 = parseCvssVector('AV:N/AC:L/Au:N/C:P/I:P/A:P');
    expect(v2.version).toBe('2.0');
    expect(v2.metrics.find((m) => m.key === 'C').text).toBe('Partial');
  });

  it.each([
    [null],
    [undefined],
    [''],
    ['garbage'],
    ['CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'],
    ['CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'], // unknown value
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N'], // missing metric
    ['CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'], // duplicate
    ['CVSS:3.1/AV'], // no colon
    [12345],
  ])('returns null for malformed vector %p', (v) => {
    expect(parseCvssVector(v)).toBeNull();
  });

  it('does not treat prototype keys as valid values', () => {
    expect(parseCvssVector('CVSS:3.1/AV:constructor/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')).toBeNull();
  });
});
