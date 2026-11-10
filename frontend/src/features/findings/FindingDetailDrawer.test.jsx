import { useState } from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

vi.mock('../../api/findings.js', () => ({
  getFinding: vi.fn(),
  updateFinding: vi.fn(),
  listFindings: vi.fn(),
}));

import { getFinding, updateFinding } from '../../api/findings.js';
import { ApiError } from '../../api/client.js';
import FindingDetailDrawer from './FindingDetailDrawer.jsx';
import { makeFinding } from '../../test/fixtures.js';

function Harness({ role = 'analyst' }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button onClick={() => setOpen(true)}>open-it</button>
      {open && <FindingDetailDrawer findingId="abc" role={role} onClose={() => setOpen(false)} />}
    </>
  );
}

async function openDrawer(role) {
  const user = userEvent.setup();
  render(<Harness role={role} />);
  await user.click(screen.getByRole('button', { name: 'open-it' }));
  await screen.findByRole('dialog');
  return user;
}

beforeEach(() => {
  vi.resetAllMocks();
  getFinding.mockResolvedValue(makeFinding());
});

describe('FindingDetailDrawer', () => {
  it('renders the fields of a finding with correct a11y attributes', async () => {
    await openDrawer('analyst');
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    const title = await screen.findByRole('heading', { name: 'GHSA-hrpp-h998-j3pp' });
    expect(dialog).toHaveAttribute('aria-labelledby', title.id);

    expect(screen.getByText('qs vulnerable to Prototype Pollution')).toBeInTheDocument();
    expect(screen.getAllByText('High').length).toBeGreaterThanOrEqual(1); // header badge (+ CVE badge)
    expect(screen.getByText('CVSS 7.5')).toBeInTheDocument();
    expect(screen.getByTestId('cvss-vector')).toHaveTextContent('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H');
    expect(screen.getByText('Network')).toBeInTheDocument(); // AV:N breakdown
    expect(screen.getByText(/taken from OSV advisory/)).toBeInTheDocument();
    expect(screen.getByText('qs@6.5.2', { selector: 'strong' })).toBeInTheDocument();
    expect(screen.getByText('Transitive')).toBeInTheDocument();
    // dependency path chain
    const path = screen.getByRole('list', { name: 'Dependency path' });
    expect(within(path).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'express@4.17.1', 'body-parser@1.19.0', 'qs@6.5.2',
    ]);
    // upgrade command
    expect(screen.getByTestId('cmd-npm')).toHaveTextContent('npm install qs@6.10.3');
    // CVE
    expect(screen.getByRole('link', { name: 'CVE-2022-24999' })).toHaveAttribute('href', 'https://www.cve.org/CVERecord?id=CVE-2022-24999');
    expect(screen.getByText(/Source: CISA-ADP/)).toBeInTheDocument();
    expect(screen.getByText('CWE-1321')).toBeInTheDocument();
  });

  it('renders advisory details as plain text (no HTML injection)', async () => {
    await openDrawer('analyst');
    await screen.findByText(/Line one of advisory/);
    expect(document.querySelector('b')).toBeNull();
    expect(screen.getByText(/<b>not bold<\/b>/)).toBeInTheDocument();
  });

  it('closes on Escape and returns focus to the opener', async () => {
    const user = await openDrawer('analyst');
    await screen.findByRole('heading', { name: 'GHSA-hrpp-h998-j3pp' });
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'open-it' })).toHaveFocus();
  });

  it('closes via the close button and returns focus; focus starts inside the drawer', async () => {
    const user = await openDrawer('analyst');
    expect(screen.getByRole('dialog')).toContainElement(document.activeElement);
    await user.click(screen.getByRole('button', { name: /close finding details/i }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'open-it' })).toHaveFocus();
  });

  it('closes when the backdrop is clicked', async () => {
    const user = await openDrawer('analyst');
    await user.click(screen.getByTestId('drawer-backdrop'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('traps focus inside the dialog', async () => {
    const user = await openDrawer('analyst');
    await screen.findByRole('heading', { name: 'GHSA-hrpp-h998-j3pp' });
    const dialog = screen.getByRole('dialog');
    for (let i = 0; i < 25; i += 1) {
      await user.tab();
      expect(dialog).toContainElement(document.activeElement);
    }
    for (let i = 0; i < 25; i += 1) {
      await user.tab({ shift: true });
      expect(dialog).toContainElement(document.activeElement);
    }
  });

  it('hides ignore for role viewer', async () => {
    await openDrawer('viewer');
    await screen.findByRole('heading', { name: 'GHSA-hrpp-h998-j3pp' });
    expect(screen.queryByRole('button', { name: /ignore finding/i })).not.toBeInTheDocument();
  });

  it('hides re-open for role viewer but still shows the ignore reason', async () => {
    getFinding.mockResolvedValue(
      makeFinding({ status: 'ignored', ignore: { reason: 'Only used in tests', by: 'u1', at: '2026-11-05T14:20:00.000Z' } }),
    );
    await openDrawer('viewer');
    expect(await screen.findByTestId('ignore-reason')).toHaveTextContent('Only used in tests');
    expect(screen.queryByRole('button', { name: 'Re-open' })).not.toBeInTheDocument();
  });

  it('blocks a too-short reason and does not call the API', async () => {
    const user = await openDrawer('analyst');
    await user.click(await screen.findByRole('button', { name: 'Ignore finding' }));
    await user.type(screen.getByLabelText(/reason/i), 'abc');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/at least 5 characters/);
    expect(screen.queryByRole('button', { name: 'Confirm ignore' })).not.toBeInTheDocument();
    expect(updateFinding).not.toHaveBeenCalled();
  });

  it('blocks a too-long reason', async () => {
    const user = await openDrawer('analyst');
    await user.click(await screen.findByRole('button', { name: 'Ignore finding' }));
    await user.click(screen.getByLabelText(/reason/i));
    await user.paste('x'.repeat(501));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/under 500/);
    expect(updateFinding).not.toHaveBeenCalled();
  });

  it('calls the API with {status:"ignored", reason} after the confirm step', async () => {
    const updated = makeFinding({
      status: 'ignored',
      ignore: { reason: 'Only used in tests', by: 'u1', at: '2026-11-10T10:00:00.000Z' },
    });
    updateFinding.mockResolvedValue(updated);
    const user = await openDrawer('analyst');
    await user.click(await screen.findByRole('button', { name: 'Ignore finding' }));
    await user.type(screen.getByLabelText(/reason/i), '  Only used in tests  ');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(updateFinding).not.toHaveBeenCalled(); // confirm step first
    await user.click(screen.getByRole('button', { name: 'Confirm ignore' }));
    await waitFor(() => expect(updateFinding).toHaveBeenCalledWith('6651000000000000000000aa', { status: 'ignored', reason: 'Only used in tests' }));
    expect(await screen.findByRole('button', { name: 'Re-open' })).toBeInTheDocument();
  });

  it('re-opens an ignored finding with {status:"open"}', async () => {
    getFinding.mockResolvedValue(makeFinding({ status: 'ignored', ignore: { reason: 'Only used in tests', by: 'u1', at: '2026-11-05T14:20:00.000Z' } }));
    updateFinding.mockResolvedValue(makeFinding());
    const user = await openDrawer('admin');
    await user.click(await screen.findByRole('button', { name: 'Re-open' }));
    expect(updateFinding).toHaveBeenCalledWith('6651000000000000000000aa', { status: 'open' });
    expect(await screen.findByRole('button', { name: 'Ignore finding' })).toBeInTheDocument();
  });

  it('does not render a javascript: reference as a link, but keeps safe ones', async () => {
    getFinding.mockResolvedValue(
      makeFinding({
        references: [
          { type: 'WEB', url: 'javascript:alert(1)' },
          { type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-hrpp-h998-j3pp' },
        ],
      }),
    );
    await openDrawer('analyst');
    const safe = await screen.findByRole('link', { name: 'https://github.com/advisories/GHSA-hrpp-h998-j3pp' });
    expect(safe).toHaveAttribute('rel', 'noopener noreferrer');
    expect(safe).toHaveAttribute('target', '_blank');
    expect(document.querySelector('a[href^="javascript:"]')).toBeNull();
    expect(screen.getByText('javascript:alert(1)').closest('a')).toBeNull();
  });

  it('shows a muted note for a CVE with UPSTREAM_UNAVAILABLE', async () => {
    getFinding.mockResolvedValue(makeFinding({ cves: [{ cveId: 'CVE-2020-28493', error: 'UPSTREAM_UNAVAILABLE' }] }));
    await openDrawer('analyst');
    expect(await screen.findByText(/temporarily unavailable/i)).toBeInTheDocument();
    expect(screen.getByText('CVE-2020-28493')).toBeInTheDocument();
  });

  it('shows unknown severity without a score', async () => {
    getFinding.mockResolvedValue(makeFinding({ severity: 'unknown', score: null, cvssVector: null, scoreSource: null, cves: [], recommendedFix: null, fixedVersions: [], hasFix: false }));
    await openDrawer('analyst');
    expect(await screen.findByText('Unknown')).toBeInTheDocument();
    expect(screen.getByText('No CVSS score')).toBeInTheDocument();
    expect(screen.getByText(/No fixed version/)).toBeInTheDocument();
  });

  it('does not print an upgrade command for an unsafe package name', async () => {
    getFinding.mockResolvedValue(makeFinding({ package: { name: 'evil;rm -rf /', version: '1.0.0', ecosystem: 'npm', purl: 'pkg:npm/x' } }));
    await openDrawer('analyst');
    await screen.findByText(/unexpected characters/);
    expect(screen.queryByTestId('cmd-npm')).not.toBeInTheDocument();
  });

  it('shows pip and poetry commands for PyPI', async () => {
    getFinding.mockResolvedValue(
      makeFinding({ package: { name: 'urllib3', version: '1.26.4', ecosystem: 'PyPI', purl: 'pkg:pypi/urllib3@1.26.4' }, recommendedFix: '1.26.17' }),
    );
    await openDrawer('analyst');
    expect(await screen.findByTestId('cmd-pip')).toHaveTextContent('pip install "urllib3>=1.26.17"');
    expect(screen.getByTestId('cmd-poetry')).toHaveTextContent('poetry add urllib3@^1.26.17');
  });

  it('shows loading, then a not-found state', async () => {
    let reject;
    getFinding.mockReturnValue(new Promise((_, rej) => { reject = rej; }));
    await openDrawer('analyst');
    expect(screen.getByRole('status')).toHaveTextContent(/loading/i);
    reject(new ApiError('Finding not found', { code: 'NOT_FOUND', status: 404 }));
    expect(await screen.findByText('Finding not found')).toBeInTheDocument();
  });

  it('shows an error state with retry', async () => {
    getFinding.mockRejectedValueOnce(new ApiError('Boom', { code: 'INTERNAL_ERROR', status: 500 }));
    const user = await openDrawer('analyst');
    expect(await screen.findByText('Could not load this finding')).toBeInTheDocument();
    getFinding.mockResolvedValue(makeFinding());
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: 'GHSA-hrpp-h998-j3pp' })).toBeInTheDocument();
  });
});
