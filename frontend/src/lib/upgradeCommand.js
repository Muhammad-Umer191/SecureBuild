// Build copy-paste upgrade commands. Inputs are validated against a strict allow-list so an
// attacker-controlled package name can never turn into an injectable shell string.

const NAME_RE = /^[A-Za-z0-9._@/-]+$/;
const VERSION_RE = /^[A-Za-z0-9._+-]+$/;

export function isSafeName(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= 214 && NAME_RE.test(name) && !name.startsWith('-');
}

export function isSafeVersion(version) {
  return typeof version === 'string' && version.length > 0 && version.length <= 64 && VERSION_RE.test(version) && !version.startsWith('-');
}

/**
 * @returns {null | {label: string, command: string}[]}  null when the input is not safe/known
 */
export function upgradeCommands(ecosystem, name, version) {
  if (!isSafeName(name) || !isSafeVersion(version)) return null;
  if (ecosystem === 'npm') {
    return [{ label: 'npm', command: `npm install ${name}@${version}` }];
  }
  if (ecosystem === 'PyPI') {
    return [
      { label: 'pip', command: `pip install "${name}>=${version}"` },
      { label: 'poetry', command: `poetry add ${name}@^${version}` },
    ];
  }
  return null;
}
