const { parseRequirementsTxt } = require('../../../../src/services/ecosystems/pypi/requirements');
const { readSourceFile } = require('../../../../src/services/parsers/readSourceFile');
const { makeRepo, removeRepo } = require('../../helpers');

const summary = (components) => components.map((c) => `${c.name}@${c.version}${c.dev ? ' (dev)' : ''}`);

let root;
afterEach(() => removeRepo(root));

// Parses <root>/requirements.txt the way the parsers module does: includes go
// through the same safe reader.
async function parse(files) {
  root = await makeRepo(files);
  const readFile = (rel, format) => readSourceFile(root, rel, format);
  return parseRequirementsTxt(await readFile('requirements.txt', 'text'), { source: 'requirements.txt', readFile });
}

describe('requirements.txt fallback', () => {
  test('reads requirements, comments, markers, extras, continuations and --hash', async () => {
    const { components, warnings } = await parse({
      'requirements.txt': [
        '# production deps',
        'requests[socks]>=2.31.0  # http',
        'Django==4.2.7 ; python_version >= "3.8"',
        'numpy==1.26.0 \\',
        '    --hash=sha256:abc123',
        'flask',
        '-e git+https://github.com/u/x.git#egg=x',
        '--index-url https://pypi.example.com/simple',
        'https://example.com/pkg.tar.gz',
        'mylib @ https://example.com/mylib.zip',
      ].join('\n'),
    });
    expect(summary(components)).toEqual(['Django@4.2.7', 'numpy@1.26.0', 'requests@2.31.0']);
    expect(warnings).toEqual([
      'requirements.txt: skipped 2 dependencies not from the registry (git, file, link or URL): https://example.com/pkg.tar.gz, mylib',
      'requirements.txt: skipped 1 dependency with no minimum version, so the installed version cannot be estimated: flask',
      'requirements.txt: ignored 2 option lines (-e, -c, --index-url, ...): -e, --index-url',
    ]);
  });

  test('follows -r includes inside the repo, once each, and refuses to leave it', async () => {
    const { components, warnings } = await parse({
      'reqs/base.txt': 'six==1.16.0\n-r ../reqs/base.txt\n',      // includes itself: read once
      'requirements.txt': '-r reqs/base.txt\n-r ../../etc/passwd\nattrs>=23.1\n',
    });
    expect(components.map((c) => [c.name, c.version, c.source])).toEqual([
      ['attrs', '23.1', 'requirements.txt'],
      ['six', '1.16.0', 'reqs/base.txt'],
    ]);
    expect(warnings).toEqual([
      'requirements.txt: included file not read (../../etc/passwd: path is outside the repository)',
    ]);
  });

  test('stops following includes after 5 levels', async () => {
    const files = { 'requirements.txt': '-r r1.txt\n' };
    for (let i = 1; i <= 7; i += 1) files[`r${i}.txt`] = `pkg${i}==1.0\n-r r${i + 1}.txt\n`;
    const { components, warnings } = await parse(files);
    expect(components.map((c) => c.name)).toEqual(['pkg1', 'pkg2', 'pkg3', 'pkg4', 'pkg5']);
    expect(warnings).toEqual(['requirements.txt: includes nested more than 5 levels were not followed']);
  });
});
