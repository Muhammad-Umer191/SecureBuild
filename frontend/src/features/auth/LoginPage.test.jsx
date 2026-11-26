import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LoginPage from './LoginPage.jsx';
import * as authApi from '../../api/auth.js';

describe('LoginPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('validates empty email/password before calling login', async () => {
    const loginSpy = vi.spyOn(authApi, 'login');
    render(<LoginPage onAuthSuccess={vi.fn()} />);

    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Please enter your email address.');
    expect(loginSpy).not.toHaveBeenCalled();
  });

  it('submits valid login credentials and invokes onAuthSuccess', async () => {
    const fakeUser = { id: 'u1', name: 'Ahsan', email: 'ahsan@securebuild.dev', role: 'admin' };
    vi.spyOn(authApi, 'login').mockResolvedValue({ token: 'tok', user: fakeUser });
    const onAuthSuccess = vi.fn();

    render(<LoginPage onAuthSuccess={onAuthSuccess} />);
    await userEvent.type(screen.getByLabelText('Email'), 'ahsan@securebuild.dev');
    await userEvent.type(screen.getByLabelText('Password'), 'password123');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    await waitFor(() => expect(onAuthSuccess).toHaveBeenCalledWith(fakeUser));
  });

  it('switches to register tab and enforces 8-character password rule', async () => {
    render(<LoginPage onAuthSuccess={vi.fn()} />);

    await userEvent.click(screen.getByRole('tab', { name: 'Create account' }));
    await userEvent.type(screen.getByLabelText('Full name'), 'Ahsan');
    await userEvent.type(screen.getByLabelText('Email'), 'ahsan@securebuild.dev');
    await userEvent.type(screen.getByLabelText('Password'), 'short');
    await userEvent.click(screen.getByRole('button', { name: 'Create account' }));

    expect(screen.getByRole('alert')).toHaveTextContent('Password must be at least 8 characters.');
  });
});
