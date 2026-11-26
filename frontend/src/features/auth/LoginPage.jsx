import { useState } from 'react';
import { login, register } from '../../api/auth.js';
import { USE_FAKE_API } from '../../api/client.js';
import './LoginPage.css';

// Seeded demo accounts shown only when VITE_USE_FAKE_API=true so you can test roles easily.
const DEMO_ACCOUNTS = [
  { label: 'Admin', email: 'admin@securebuild.dev', password: 'password123' },
  { label: 'Analyst', email: 'analyst@securebuild.dev', password: 'password123' },
  { label: 'Viewer', email: 'viewer@securebuild.dev', password: 'password123' },
];

/**
 * Login / Register screen shown before the main SecureBuild dashboard.
 * Props: onAuthSuccess(user)
 */
export default function LoginPage({ onAuthSuccess }) {
  // Toggle between "login" and "register" modes inside the same card.
  const [mode, setMode] = useState('login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  function switchMode(nextMode) {
    setMode(nextMode);
    setError(null);
  }

  function fillDemoAccount(account) {
    setMode('login');
    setEmail(account.email);
    setPassword(account.password);
    setError(null);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    // Basic client-side checks so the user gets immediate feedback before hitting the API.
    if (mode === 'register' && !name.trim()) {
      setError('Please enter your name.');
      return;
    }
    if (!email.trim()) {
      setError('Please enter your email address.');
      return;
    }
    if (!password) {
      setError('Please enter your password.');
      return;
    }
    if (mode === 'register' && password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }

    setSubmitting(true);
    try {
      const data =
        mode === 'login'
          ? await login({ email, password })
          : await register({ name, email, password });

      onAuthSuccess(data.user);
    } catch (err) {
      setError(err?.message || 'Authentication failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="card auth-card">
        <div className="auth-card__brand">
          <span className="auth-card__logo" aria-hidden="true">SB</span>
          <div>
            <h1 className="auth-card__title">SecureBuild</h1>
            <p className="muted auth-card__subtitle">Software Supply-Chain Risk Dashboard</p>
          </div>
        </div>

        {/* Mode switcher: Sign in vs Create account */}
        <div className="auth-tabs" role="tablist" aria-label="Authentication mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'login'}
            className={`auth-tab${mode === 'login' ? ' auth-tab--active' : ''}`}
            onClick={() => switchMode('login')}
          >
            Sign in
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'register'}
            className={`auth-tab${mode === 'register' ? ' auth-tab--active' : ''}`}
            onClick={() => switchMode('register')}
          >
            Create account
          </button>
        </div>

        <form className="auth-form" onSubmit={handleSubmit} noValidate>
          {mode === 'register' && (
            <div className="auth-field">
              <label htmlFor="auth-name">Full name</label>
              <input
                id="auth-name"
                type="text"
                autoComplete="name"
                placeholder="Ahsan Nauman"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={submitting}
              />
            </div>
          )}

          <div className="auth-field">
            <label htmlFor="auth-email">Email</label>
            <input
              id="auth-email"
              type="email"
              autoComplete="email"
              placeholder="you@securebuild.dev"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={submitting}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="auth-password">Password</label>
            <input
              id="auth-password"
              type="password"
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              placeholder={mode === 'register' ? 'At least 8 characters' : 'Enter your password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={submitting}
            />
          </div>

          {error && (
            <div className="auth-error" role="alert">
              {error}
            </div>
          )}

          <button type="submit" className="btn btn--primary auth-submit" disabled={submitting}>
            {submitting
              ? mode === 'login'
                ? 'Signing in...'
                : 'Creating account...'
              : mode === 'login'
                ? 'Sign in'
                : 'Create account'}
          </button>
        </form>

        {/* Quick-fill demo accounts for local fake-API development and presentation */}
        {USE_FAKE_API && (
          <div className="auth-demo">
            <p className="muted auth-demo__label">Demo quick-fill (fake API mode):</p>
            <div className="auth-demo__buttons">
              {DEMO_ACCOUNTS.map((acc) => (
                <button
                  key={acc.label}
                  type="button"
                  className="btn btn--small"
                  onClick={() => fillDemoAccount(acc)}
                >
                  {acc.label}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
