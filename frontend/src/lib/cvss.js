// Turn a CVSS vector string into readable metrics, e.g. AV:N -> "Attack vector: Network".
// Supports CVSS 3.0 / 3.1 / 4.0 and 2.0. Returns null for anything malformed.

const V3 = {
  AV: ['Attack vector', { N: 'Network', A: 'Adjacent network', L: 'Local', P: 'Physical' }],
  AC: ['Attack complexity', { L: 'Low', H: 'High' }],
  PR: ['Privileges required', { N: 'None', L: 'Low', H: 'High' }],
  UI: ['User interaction', { N: 'None', R: 'Required' }],
  S: ['Scope', { U: 'Unchanged', C: 'Changed' }],
  C: ['Confidentiality impact', { N: 'None', L: 'Low', H: 'High' }],
  I: ['Integrity impact', { N: 'None', L: 'Low', H: 'High' }],
  A: ['Availability impact', { N: 'None', L: 'Low', H: 'High' }],
};

const V4 = {
  AV: ['Attack vector', { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }],
  AC: ['Attack complexity', { L: 'Low', H: 'High' }],
  AT: ['Attack requirements', { N: 'None', P: 'Present' }],
  PR: ['Privileges required', { N: 'None', L: 'Low', H: 'High' }],
  UI: ['User interaction', { N: 'None', P: 'Passive', A: 'Active' }],
  VC: ['Vulnerable system confidentiality', { N: 'None', L: 'Low', H: 'High' }],
  VI: ['Vulnerable system integrity', { N: 'None', L: 'Low', H: 'High' }],
  VA: ['Vulnerable system availability', { N: 'None', L: 'Low', H: 'High' }],
  SC: ['Subsequent system confidentiality', { N: 'None', L: 'Low', H: 'High' }],
  SI: ['Subsequent system integrity', { N: 'None', L: 'Low', H: 'High' }],
  SA: ['Subsequent system availability', { N: 'None', L: 'Low', H: 'High' }],
};

const V2 = {
  AV: ['Attack vector', { N: 'Network', A: 'Adjacent network', L: 'Local' }],
  AC: ['Attack complexity', { L: 'Low', M: 'Medium', H: 'High' }],
  Au: ['Authentication', { N: 'None', S: 'Single', M: 'Multiple' }],
  C: ['Confidentiality impact', { N: 'None', P: 'Partial', C: 'Complete' }],
  I: ['Integrity impact', { N: 'None', P: 'Partial', C: 'Complete' }],
  A: ['Availability impact', { N: 'None', P: 'Partial', C: 'Complete' }],
};

/**
 * @returns {null | { version: string, metrics: {key:string,label:string,value:string,text:string}[] }}
 */
export function parseCvssVector(vector) {
  if (typeof vector !== 'string' || vector.length === 0 || vector.length > 300) return null;
  const parts = vector.trim().split('/');
  let version = '2.0';
  let table = V2;
  if (parts[0].startsWith('CVSS:')) {
    version = parts.shift().slice(5);
    if (version === '3.0' || version === '3.1') table = V3;
    else if (version === '4.0') table = V4;
    else return null;
  }
  const seen = new Map();
  for (const part of parts) {
    const idx = part.indexOf(':');
    if (idx <= 0) return null;
    const key = part.slice(0, idx);
    const value = part.slice(idx + 1);
    if (seen.has(key)) return null;
    seen.set(key, value);
  }
  const metrics = [];
  for (const [key, [label, values]] of Object.entries(table)) {
    const value = seen.get(key);
    if (value === undefined) return null; // every base metric is required
    if (!Object.prototype.hasOwnProperty.call(values, value)) return null;
    metrics.push({ key, label, value, text: values[value] });
  }
  return { version, metrics };
}
