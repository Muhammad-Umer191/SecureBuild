import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

vi.mock('../../api/components.js', () => ({
  listComponents: vi.fn(),
  exportSbom: vi.fn(),
}));

import { listComponents, exportSbom } from '../../api/components.js';
import { ApiError } from '../../api/client.js';
import SbomTab from './SbomTab.jsx';
import { makeComponent, makeComponentsResponse } from '../../test/fixtures.js';

const items = [
  makeComponent(1, { name: 'qs', version: '6.5.2', purl: 'pkg:npm/qs@6.5.2', direct: false, licenses: ['BSD-3-Clause'], vulnerabilityCount: 1, maxSeverity: 'high' }),
  makeComponent(2, { name: 'express', version: '4.17.1', purl: 'pkg:npm/express@4.17.1', direct: true, licenses: [] }),
];

beforeEach(() => {
  vi.resetAllMocks();
  listComponents.mockResolvedValue(makeComponentsResponse(items, { total: 2 }));
});

afterEach(() => vi.restoreAllMocks());

describe('SbomTab', () => {
  it('renders summary cards and rows', async () => {
    render(<SbomTab repoId="r1" />);
    expect(screen.getByRole('status')).toHaveTextContent(/loading/i);

    const summary = await screen.findByRole('list', { name: 'SBOM summary' });
    const cards = within(summary).getAllByRole('listitem').map((c) => c.textContent);
    expect(cards).toEqual(expect.arrayContaining([
      '312Total components', '18Direct', '294Transitive', '7Vulnerable', '300npm packages', '12PyPI packages',
    ]));

    const rows = screen.getAllByRole('row');
    expect(rows).toHaveLength(3); // header + 2
    const qsRow = within(screen.getByRole('rowheader', { name: 'qs' }).closest('tr'));
    expect(qsRow.getByText('6.5.2')).toBeInTheDocument();
    expect(qsRow.getByText('BSD-3-Clause')).toBeInTheDocument();
    expect(qsRow.getByText('High')).toBeInTheDocument(); // text label, not colour only
    expect(qsRow.getByText('pkg:npm/qs@6.5.2')).toHaveClass('mono');
    expect(screen.getByText('Unknown', { selector: 'span.muted' })).toBeInTheDocument(); // no license info
    expect(listComponents).toHaveBeenCalledWith('r1', expect.objectContaining({ sort: 'name', order: 'asc', page: 1 }));
  });

  it('calls the API with the right params when filters change', async () => {
    const user = userEvent.setup();
    render(<SbomTab repoId="r1" />);
    await screen.findByRole('table');

    await user.selectOptions(screen.getByLabelText('Ecosystem'), 'npm');
    await waitFor(() => expect(listComponents).toHaveBeenLastCalledWith('r1', expect.objectContaining({ ecosystem: 'npm' })));

    await user.selectOptions(screen.getByLabelText('Dependency type'), 'false');
    await waitFor(() => expect(listComponents).toHaveBeenLastCalledWith('r1', expect.objectContaining({ ecosystem: 'npm', direct: 'false' })));

    await user.click(screen.getByLabelText('Vulnerable only'));
    await waitFor(() => expect(listComponents).toHaveBeenLastCalledWith('r1', expect.objectContaining({ vulnerable: 'true' })));

    await user.click(screen.getByRole('button', { name: /vulnerabilities/i }));
    await waitFor(() => expect(listComponents).toHaveBeenLastCalledWith('r1', expect.objectContaining({ sort: 'vulns', order: 'desc', page: 1 })));
  });

  it('debounces the search box', async () => {
    const user = userEvent.setup();
    render(<SbomTab repoId="r1" />);
    await screen.findByRole('table');
    listComponents.mockClear();

    await user.type(screen.getByLabelText('Search'), 'lodash');
    expect(listComponents).not.toHaveBeenCalled(); // not on every keystroke
    await waitFor(() => expect(listComponents).toHaveBeenCalledTimes(1), { timeout: 2000 });
    expect(listComponents).toHaveBeenCalledWith('r1', expect.objectContaining({ q: 'lodash' }));
  });

  it('paginates', async () => {
    listComponents.mockResolvedValue(makeComponentsResponse(items, { total: 45, limit: 20 }));
    const user = userEvent.setup();
    render(<SbomTab repoId="r1" />);
    await screen.findByText('Page 1 of 3');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(listComponents).toHaveBeenLastCalledWith('r1', expect.objectContaining({ page: 2 })));
  });

  it('shows an empty state with a way to clear filters', async () => {
    listComponents.mockResolvedValue(makeComponentsResponse([], { total: 0 }));
    const user = userEvent.setup();
    render(<SbomTab repoId="r1" />);
    await user.click(await screen.findByLabelText('Vulnerable only'));
    expect(await screen.findByText('No components match these filters')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(screen.getByLabelText('Vulnerable only')).not.toBeChecked());
  });

  it('shows the no-scan state', async () => {
    listComponents.mockRejectedValue(new ApiError('No completed scan', { code: 'NO_SCAN', status: 404 }));
    render(<SbomTab repoId="r1" />);
    expect(await screen.findByText('No completed scan yet')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Export CycloneDX' })).toBeDisabled();
  });

  it('shows an error state with retry', async () => {
    listComponents.mockRejectedValueOnce(new ApiError('Server exploded', { code: 'INTERNAL_ERROR', status: 500 }));
    const user = userEvent.setup();
    render(<SbomTab repoId="r1" />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Server exploded');
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('table')).toBeInTheDocument();
  });

  it('exports CycloneDX: fetches the blob and triggers a download, then revokes the URL', async () => {
    const blob = new Blob(['{}'], { type: 'application/json' });
    exportSbom.mockResolvedValue({ blob, filename: 'acme-demo-sbom.cdx.json' });
    URL.createObjectURL = vi.fn(() => 'blob:fake');
    URL.revokeObjectURL = vi.fn();
    let downloaded = null;
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click() {
      downloaded = { href: this.href, download: this.download };
    });

    const user = userEvent.setup();
    render(<SbomTab repoId="r1" />);
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: 'Export CycloneDX' }));

    await waitFor(() => expect(clickSpy).toHaveBeenCalled());
    expect(exportSbom).toHaveBeenCalledWith('r1', undefined);
    expect(URL.createObjectURL).toHaveBeenCalledWith(blob);
    expect(downloaded).toEqual({ href: 'blob:fake', download: 'acme-demo-sbom.cdx.json' });
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:fake');
  });

  it('shows an error when export fails', async () => {
    exportSbom.mockRejectedValue(new ApiError('Too many requests', { code: 'RATE_LIMITED', status: 429 }));
    const user = userEvent.setup();
    render(<SbomTab repoId="r1" />);
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: 'Export CycloneDX' }));
    expect(await screen.findByText('Too many requests')).toBeInTheDocument();
  });
});
