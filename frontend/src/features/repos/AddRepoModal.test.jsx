import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import AddRepoModal from './AddRepoModal.jsx';
import * as reposApi from '../../api/repos.js';

describe('AddRepoModal', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('rejects non-GitHub URLs locally before calling addRepo', async () => {
    const addSpy = vi.spyOn(reposApi, 'addRepo');
    render(<AddRepoModal onClose={vi.fn()} onAdded={vi.fn()} />);

    await userEvent.type(screen.getByLabelText('GitHub repository URL'), 'https://gitlab.com/acme/app');
    await userEvent.click(screen.getByRole('button', { name: 'Add repository' }));

    expect(screen.getByRole('alert')).toHaveTextContent('Use a valid GitHub URL');
    expect(addSpy).not.toHaveBeenCalled();
  });

  it('normalizes valid GitHub URL and passes created repo to onAdded', async () => {
    const created = { id: 'r9', name: 'acme/app', url: 'https://github.com/acme/app' };
    const addSpy = vi.spyOn(reposApi, 'addRepo').mockResolvedValue(created);
    const onAdded = vi.fn();

    render(<AddRepoModal onClose={vi.fn()} onAdded={onAdded} />);
    await userEvent.type(screen.getByLabelText('GitHub repository URL'), 'https://github.com/acme/app/');
    await userEvent.click(screen.getByRole('button', { name: 'Add repository' }));

    expect(addSpy).toHaveBeenCalledWith({ url: 'https://github.com/acme/app' });
    await waitFor(() => expect(onAdded).toHaveBeenCalledWith(created));
  });
});
