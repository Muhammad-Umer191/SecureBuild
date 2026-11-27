// Runs git as a locked-down child process.
//
// - execFile with an argument array, never a shell string, so text inside
//   arguments can't run as a command.
// - A minimal environment: no server secrets, no user/system git config,
//   no stored credentials (private repos are unreachable), no password prompts.
// - Safety config on every call: https only, hooks off, symlinks checked out
//   as plain text files.
const { execFile } = require('node:child_process');
const os = require('node:os');

// Only what git needs. process.env is not passed on, so secrets like
// JWT_SECRET or MONGO_URI never reach the child process.
const GIT_ENV = {
  PATH: process.env.PATH,
  ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
  GIT_TERMINAL_PROMPT: '0',       // fail instead of asking for a password
  GIT_CONFIG_NOSYSTEM: '1',       // ignore /etc/gitconfig
  // Windows Git rejects '\\.\nul' (os.devNull) in GIT_CONFIG_GLOBAL with Invalid argument.
  GIT_CONFIG_GLOBAL: process.platform === 'win32' ? '' : os.devNull,
  GIT_LFS_SKIP_SMUDGE: '1',       // don't download large LFS files
};

// Passed as "-c key=value" before the git command.
const GIT_SAFETY_CONFIG = [
  `core.hooksPath=${os.devNull}`,
  'credential.helper=',           // clear any credential helper (e.g. macOS keychain)
  'protocol.allow=never',
  'protocol.https.allow=always',
  'core.symlinks=false',
];

/**
 * Runs `git <safety config> <args>`.
 * Resolves with trimmed stdout; rejects with the execFile error, plus `stderr`.
 * `err.killed` is true when git was stopped (timeout or kill).
 *
 * @param {string[]} args
 * @param {Object} [opts]
 * @param {string} [opts.cwd]
 * @param {number} [opts.timeoutMs]
 * @param {(child: import('node:child_process').ChildProcess) => void} [opts.onSpawn]
 *        receives the process, e.g. to kill it early
 */
function runGit(args, { cwd, timeoutMs, onSpawn } = {}) {
  const fullArgs = [...GIT_SAFETY_CONFIG.flatMap((kv) => ['-c', kv]), ...args];
  return new Promise((resolve, reject) => {
    const child = execFile(
      'git',
      fullArgs,
      { cwd, env: GIT_ENV, timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          err.stderr = stderr;
          return reject(err);
        }
        return resolve(stdout.trim());
      },
    );
    if (onSpawn) onSpawn(child);
  });
}

module.exports = { runGit };
