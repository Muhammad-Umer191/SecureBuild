// Wording for user-facing warnings, kept short even for big repos.

const MAX_LISTED = 5;

/** "a, b, c, d, e, and 3 more" */
const listNames = (names) =>
  `${names.slice(0, MAX_LISTED).join(', ')}${names.length > MAX_LISTED ? `, and ${names.length - MAX_LISTED} more` : ''}`;

/**
 * Up to 5 messages are kept as they are; more are folded into one summary line.
 * @param {{path: string, text: string}[]} messages
 * @param {(paths: string[]) => string} summarize
 */
function capMessages(messages, summarize) {
  if (messages.length <= MAX_LISTED) return messages.map((m) => m.text);
  return [summarize(messages.map((m) => m.path))];
}

const SKIP_REASONS = {
  nonRegistry: 'not from the registry (git, file, link or URL)',
  unbounded: 'with no minimum version, so the installed version cannot be estimated',
  invalid: 'with a version we could not read',
};

/**
 * One warning line per reason, e.g.
 * "package.json: skipped 2 dependencies not from the registry (...): a, b"
 * @param {string} source
 * @param {{[reason: string]: string[]}} skipped  names grouped by reason (see SKIP_REASONS, plus 'options')
 */
function skippedWarnings(source, skipped) {
  const warnings = Object.keys(SKIP_REASONS)
    .filter((reason) => skipped[reason] && skipped[reason].length)
    .map((reason) => {
      const names = skipped[reason];
      const what = names.length === 1 ? '1 dependency' : `${names.length} dependencies`;
      return `${source}: skipped ${what} ${SKIP_REASONS[reason]}: ${listNames(names)}`;
    });
  if (skipped.options && skipped.options.length) {
    const n = skipped.options.length;
    warnings.push(`${source}: ignored ${n} option line${n === 1 ? '' : 's'} (-e, -c, --index-url, ...): ${listNames(skipped.options)}`);
  }
  return warnings;
}

module.exports = { listNames, capMessages, skippedWarnings };
