import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import FindingsTab from './FindingsTab.jsx';
import * as findingsApi from '../../api/findings.js';

const MOCK_RESPONSE = {
  scan: { id: 's1', finishedAt: '2026-11-10T09:12:00.000Z', commitSha: 'a1b2c3d' },
  items: [
    {
      id: 'f1',
      vulnId: 'GHSA-jf85-cpcp-j695',
      cveIds: ['CVE-2019-10744'],
      summary: 'Prototype Pollution in lodash',
      package: { name: 'lodash', version: '4.17.11', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.11' },
      direct: true,
      severity: 'critical',
      score: 9.1,
      hasFix: true,
      recommendedFix: '4.17.12',
      status: 'open',
      published: '2019-07-26T00:00:00.000Z',
    },
  ],
  page: 1,
  limit: 10,
  total: 1,
  counts: { critical: 1, high: 2, medium: 1, low: 0, none: 0, unknown: 0 },
};

describe('FindingsTab', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders severity summary cards and findings table, and opens drawer on click', async () => {
    vi.spyOn(findingsApi, 'listFindings').mockResolvedValue(MOCK_RESPONSE);
    const onOpenFinding = vi.fn();

    render(<FindingsTab repoId="r1" statusFilter="open" onOpenFinding={onOpenFinding} />);

    expect(await screen.findByText('GHSA-jf85-cpcp-j695')).toBeInTheDocument();
    expect(screen.getByText('Total open')).toBeInTheDocument();
    expect(screen.getByText('4.17.12')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'GHSA-jf85-cpcp-j695' }));
    expect(onOpenFinding).toHaveBeenCalledWith('f1');
  });

  it('filters by severity card click and resets filters cleanly', async () => {
    const spy = vi.spyOn(findingsApi, 'listFindings').mockResolvedValue(MOCK_RESPONSE);

    render(<FindingsTab repoId="r1" statusFilter="open" onOpenFinding={vi.fn()} />);
    await screen.findByText('GHSA-jf85-cpcp-j695');

    await userEvent.click(screen.getByRole('listitem', { name: /Critical/i }));
    await waitFor(() =>
      expect(spy).toHaveBeenLastCalledWith(
        'r1',
        expect.objectContaining({ status: 'open', severity: 'critical', page: 1 }),
      ),
    );

    await userEvent.click(screen.getByRole('button', { name: 'Reset filters' }));
    await waitFor(() =>
      expect(spy).toHaveBeenLastCalledWith(
        'r1',
        expect.not.objectContaining({ severity: 'critical' }),
      ),
    );
  });
});
