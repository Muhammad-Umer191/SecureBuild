const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { dirSize, watchDirSize } = require('../../../src/services/clone/dirSize');

let tmp;
beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'sb-size-'));
});
afterEach(() => fs.rm(tmp, { recursive: true, force: true }));

describe('dirSize', () => {
  test('counts nested files and does not follow symlinks', async () => {
    await fs.mkdir(path.join(tmp, 'a/b'), { recursive: true });
    await fs.writeFile(path.join(tmp, 'one.txt'), 'x'.repeat(100));
    await fs.writeFile(path.join(tmp, 'a/b/two.txt'), 'y'.repeat(50));
    await fs.symlink('/usr/bin', path.join(tmp, 'link'));
    expect(await dirSize(tmp)).toBe(150);
  });

  test('a missing folder counts as 0', async () => {
    expect(await dirSize(path.join(tmp, 'nope'))).toBe(0);
  });
});

describe('watchDirSize', () => {
  test('calls onExceed once when the folder grows past the limit', async () => {
    const onExceed = jest.fn();
    const stop = watchDirSize(tmp, 100, onExceed, 20);
    await fs.writeFile(path.join(tmp, 'big.txt'), 'x'.repeat(500));
    await new Promise((r) => setTimeout(r, 150));
    stop();
    expect(onExceed).toHaveBeenCalledTimes(1);
  });

  test('stays quiet under the limit', async () => {
    const onExceed = jest.fn();
    const stop = watchDirSize(tmp, 1000, onExceed, 20);
    await fs.writeFile(path.join(tmp, 'small.txt'), 'x'.repeat(10));
    await new Promise((r) => setTimeout(r, 100));
    stop();
    expect(onExceed).not.toHaveBeenCalled();
  });
});
