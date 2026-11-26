const { createOsvClient, OsvError } = require('../../../src/services/osv/osvClient');
const { fakeFetch } = require('./fakeOsv');

// Answers with the given responses in order (an Error = network failure).
function sequence(...responses) {
  let i = 0;
  return fakeFetch(() => {
    const r = responses[Math.min(i, responses.length - 1)];
    i += 1;
    if (r instanceof Error) throw r;
    return r;
  });
}

const timeoutError = () => Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });

describe('createOsvClient', () => {
  test('retries 503s and returns the eventual success', async () => {
    const fake = sequence({ status: 503 }, { status: 503 }, { status: 200, body: { ok: true } });
    const sleep = jest.fn(() => Promise.resolve());
    const client = createOsvClient({ fetch: fake.fetch, sleep });
    await expect(client.getJson('/vulns/X')).resolves.toEqual({ status: 200, body: { ok: true } });
    expect(fake.calls).toHaveLength(3);
    // exponential backoff: ~500ms then ~1000ms (plus up to 250ms jitter)
    expect(sleep.mock.calls[0][0]).toBeGreaterThanOrEqual(500);
    expect(sleep.mock.calls[0][0]).toBeLessThan(750);
    expect(sleep.mock.calls[1][0]).toBeGreaterThanOrEqual(1000);
    expect(sleep.mock.calls[1][0]).toBeLessThan(1250);
  });

  test('honours Retry-After on 429, capped at 30s', async () => {
    const sleep = jest.fn(() => Promise.resolve());
    const fake = sequence(
      { status: 429, headers: { 'retry-after': '7' } },
      { status: 429, headers: { 'retry-after': '600' } },
      { status: 200, body: {} },
    );
    await createOsvClient({ fetch: fake.fetch, sleep }).getJson('/x');
    expect(sleep.mock.calls.map((c) => c[0])).toEqual([7000, 30000]);
  });

  test('an unusable Retry-After (e.g. an HTTP date) falls back to backoff', async () => {
    const sleep = jest.fn(() => Promise.resolve());
    const fake = sequence({ status: 429, headers: { 'retry-after': 'Wed, 21 Oct 2026 07:28:00 GMT' } }, { status: 200, body: {} });
    await createOsvClient({ fetch: fake.fetch, sleep }).getJson('/x');
    expect(sleep.mock.calls[0][0]).toBeGreaterThanOrEqual(500);
  });

  test('retries network errors and timeouts', async () => {
    const fake = sequence(new Error('ECONNRESET'), timeoutError(), { status: 200, body: { ok: 1 } });
    const client = createOsvClient({ fetch: fake.fetch, sleep: () => Promise.resolve() });
    await expect(client.getJson('/x')).resolves.toMatchObject({ status: 200 });
    expect(fake.calls).toHaveLength(3);
  });

  test('gives up after 4 attempts with OSV_UNAVAILABLE', async () => {
    const fake = sequence({ status: 502 });
    const client = createOsvClient({ fetch: fake.fetch, sleep: () => Promise.resolve() });
    const err = await client.getJson('/x').catch((e) => e);
    expect(err).toBeInstanceOf(OsvError);
    expect(err).toMatchObject({ code: 'OSV_UNAVAILABLE', permanent: false });
    expect(err.message).toBe('OSV.dev GET /x failed after 4 attempts (HTTP 502)');
    expect(fake.calls).toHaveLength(4);
  });

  test('describes a timeout in the final error', async () => {
    const fake = sequence(timeoutError());
    const err = await createOsvClient({ fetch: fake.fetch, sleep: () => Promise.resolve(), timeoutMs: 5000 })
      .getJson('/x').catch((e) => e);
    expect(err.message).toMatch(/timed out after 5s/);
  });

  test('does not retry other 4xx answers; returns them to the caller', async () => {
    const fake = sequence({ status: 404, body: { message: 'Vulnerability not found' } });
    const result = await createOsvClient({ fetch: fake.fetch, sleep: () => Promise.resolve() }).getJson('/vulns/NOPE');
    expect(result).toEqual({ status: 404, body: { message: 'Vulnerability not found' } });
    expect(fake.calls).toHaveLength(1);
  });

  test('a 200 that is not JSON is OSV_BAD_RESPONSE', async () => {
    const fake = sequence({ status: 200, body: '<html>maintenance</html>' });
    await expect(createOsvClient({ fetch: fake.fetch }).getJson('/x')).rejects.toMatchObject({ code: 'OSV_BAD_RESPONSE' });
  });

  test('sends JSON bodies on POST', async () => {
    const fake = sequence({ status: 200, body: {} });
    await createOsvClient({ fetch: fake.fetch }).postJson('/querybatch', { queries: [] });
    expect(fake.calls[0]).toEqual({ method: 'POST', path: '/querybatch', body: { queries: [] } });
  });
});
