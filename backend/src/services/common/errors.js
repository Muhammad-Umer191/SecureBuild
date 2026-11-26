// Errors shared across modules.

/** A problem with one input file. The message is shown to the user as a warning. */
class ParseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ParseError';
  }
}

module.exports = { ParseError };
