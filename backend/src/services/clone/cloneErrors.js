// Errors raised while cloning, with a machine-readable code.

/** `permanent` = retrying won't help (bad URL, private repo, too large). */
class CloneError extends Error {
  constructor(code, message, { permanent = false } = {}) {
    super(message);
    this.name = 'CloneError';
    this.code = code;
    this.permanent = permanent;
  }
}

/** Turns git's error output into a CloneError the caller can act on. */
function mapGitError(stderr) {
  const text = stderr || '';
  // GitHub answers "authentication required" for both private and missing repos.
  if (/Repository not found|could not read Username|Authentication failed|terminal prompts disabled/i.test(text)) {
    return new CloneError('REPO_NOT_FOUND', 'Repository not found or not public', { permanent: true });
  }
  if (/Could not resolve host|Failed to connect|Connection (timed out|refused|reset)|unable to access/i.test(text)) {
    return new CloneError('NETWORK_ERROR', 'Could not reach GitHub');
  }
  const lastLine = text.trim().split('\n').pop() || 'unknown error';
  return new CloneError('CLONE_FAILED', `git clone failed: ${lastLine.slice(0, 200)}`);
}

module.exports = { CloneError, mapGitError };
