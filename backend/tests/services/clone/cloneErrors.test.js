const { CloneError, mapGitError } = require('../../../src/services/clone/cloneErrors');

describe('mapGitError', () => {
  test('private or missing repo is a permanent REPO_NOT_FOUND', () => {
    const err = mapGitError("fatal: could not read Username for 'https://github.com': terminal prompts disabled");
    expect(err).toBeInstanceOf(CloneError);
    expect(err).toMatchObject({ code: 'REPO_NOT_FOUND', permanent: true });
  });

  test('network problems can be retried', () => {
    const err = mapGitError("fatal: unable to access 'https://github.com/a/b.git/': Could not resolve host: github.com");
    expect(err).toMatchObject({ code: 'NETWORK_ERROR', permanent: false });
  });

  test('anything else keeps the last line of git output', () => {
    expect(mapGitError('warning: x\nfatal: something odd').message).toBe('git clone failed: fatal: something odd');
  });

  test('empty output still gives an error', () => {
    expect(mapGitError(undefined)).toMatchObject({ code: 'CLONE_FAILED' });
  });
});
