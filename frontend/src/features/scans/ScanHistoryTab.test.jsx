import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ScanHistoryTab from './ScanHistoryTab.jsx';
import * as scansApi from '../../api/scans.js';

describe('ScanHistoryTab', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders completed and failed scan runs', async () => {
    vi.spyOn(scansApi, 'listScans').mockResolvedValue({
      items: [
        {
          id: 's1',
          status: 'completed',
          commitSha: 'a1b2c3d',
          startedAt: '2026-11-10T09:11:10.000Z',
          finishedAt: '2026-11-10T09:12:00.000Z',
          error: null,
          findingsCount: 12,
          componentsCount: 40,
        },
        {
          id: 's2',
          status: 'failed',
          commitSha: '77c10e2',
          startedAt: '2026-11-08T16:20:00.000Z',
          finishedAt: '2026-11-08T16:20:08.000Z',
          error: 'Lockfile missing',
          findingsCount: 0,
          componentsCount: 0,
        },
      ],
    });

    render(<ScanHistoryTab repoId="r1" />);

    expect(await screen.findByText('Completed')).toBeInTheDocument();
    expect(screen.getByText('Failed')).toBeInTheDocument();
    expect(screen.getByText('a1b2c3d')).toBeInTheDocument();
    expect(screen.getByText('Lockfile missing')).toBeInTheDocument();
  });

  it('shows error state and retries when Try again is clicked', async () => {
    const spy = vi
      .spyOn(scansApi, 'listScans')
      .mockRejectedValueOnce(new Error('Network down'))
      .mockResolvedValueOnce({ items: [] });

    render(<ScanHistoryTab repoId="r1" />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Network down');
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await screen.findByText('No scans recorded yet')).toBeInTheDocument();
    expect(spy).toHaveBeenCalledTimes(2);
  });
});
