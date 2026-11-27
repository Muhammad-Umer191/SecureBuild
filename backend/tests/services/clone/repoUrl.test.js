const { parseRepoUrl, isValidRepoUrl } = require('../../../src/services/clone/repoUrl');

describe('isValidRepoUrl', () => {
  test.each([
    'https://github.com/octocat/Hello-World',
    'https://github.com/octocat/Hello-World.git',
    'https://github.com/octocat/Hello-World/',
    'https://github.com/a-b/repo.name_x',
  ])('accepts %s', (url) => {
    expect(isValidRepoUrl(url)).toBe(true);
  });

  test.each([
    ['plain http', 'http://github.com/octocat/Hello-World'],
    ['other host', 'https://gitlab.com/octocat/Hello-World'],
    ['look-alike host', 'https://github.com.evil.com/octocat/Hello-World'],
    ['credentials in URL', 'https://user:pass@github.com/octocat/Hello-World'],
    ['ssh', 'git@github.com:octocat/Hello-World.git'],
    ['file protocol', 'file:///etc/passwd'],
    ['extra path segment', 'https://github.com/octocat/Hello-World/tree/main'],
    ['query string', 'https://github.com/octocat/Hello-World?x=1'],
    ['owner starting with "-"', 'https://github.com/-evil/repo'],
    ['repo ".."', 'https://github.com/octocat/..'],
    ['shell characters', 'https://github.com/octocat/repo;rm -rf /'],
    ['option injection', '--upload-pack=touch /tmp/pwned'],
    ['empty', ''],
    ['not a string', 42],
  ])('rejects %s', (_label, url) => {
    expect(isValidRepoUrl(url)).toBe(false);
  });
});

describe('parseRepoUrl', () => {
  test('builds a canonical clone URL', () => {
    expect(parseRepoUrl('https://github.com/octocat/Hello-World/')).toEqual({
      owner: 'octocat', repo: 'Hello-World', cloneUrl: 'https://github.com/octocat/Hello-World.git',
    });
  });
});
