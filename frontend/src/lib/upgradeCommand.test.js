import { describe, it, expect } from 'vitest';
import { upgradeCommands } from './upgradeCommand.js';

describe('upgradeCommands', () => {
  it('builds the npm command', () => {
    expect(upgradeCommands('npm', 'qs', '6.10.3')).toEqual([{ label: 'npm', command: 'npm install qs@6.10.3' }]);
  });

  it('supports scoped npm packages', () => {
    expect(upgradeCommands('npm', '@scope/pkg', '1.2.3')[0].command).toBe('npm install @scope/pkg@1.2.3');
  });

  it('builds pip and poetry commands for PyPI', () => {
    expect(upgradeCommands('PyPI', 'urllib3', '1.26.17')).toEqual([
      { label: 'pip', command: 'pip install "urllib3>=1.26.17"' },
      { label: 'poetry', command: 'poetry add urllib3@^1.26.17' },
    ]);
  });

  it.each([
    'bad name',
    'foo;rm -rf /',
    'foo$(whoami)',
    'foo`id`',
    'foo&&bar',
    'foo"bar',
    "foo'bar",
    'foo|bar',
    '-rf',
    '',
    'foo\nbar',
  ])('rejects unsafe package name %p', (name) => {
    expect(upgradeCommands('npm', name, '1.0.0')).toBeNull();
    expect(upgradeCommands('PyPI', name, '1.0.0')).toBeNull();
  });

  it('rejects unsafe versions and unknown ecosystems', () => {
    expect(upgradeCommands('npm', 'qs', '1.0.0; rm -rf /')).toBeNull();
    expect(upgradeCommands('npm', 'qs', '')).toBeNull();
    expect(upgradeCommands('npm', 'qs', null)).toBeNull();
    expect(upgradeCommands('maven', 'qs', '1.0.0')).toBeNull();
    expect(upgradeCommands('npm', undefined, '1.0.0')).toBeNull();
  });
});
