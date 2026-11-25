import { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { addRepo, validateRepoUrl } from '../../api/repos.js';
import './AddRepoModal.css';

/**
 * Modal dialog for adding a GitHub repository to the dashboard.
 * Props: onClose(), onAdded(newRepo)
 */
export default function AddRepoModal({ onClose, onAdded }) {
  const titleId = useId();
  const inputRef = useRef(null);
  const [url, setUrl] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  // Auto-focus the URL input when the modal opens, and close on Escape.
  useEffect(() => {
    inputRef.current?.focus();

    function onKeyDown(e) {
      if (e.key === 'Escape' && !submitting) {
        onClose();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose, submitting]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    const check = validateRepoUrl(url);
    if (!check.valid) {
      setError(check.error);
      return;
    }

    setSubmitting(true);
    try {
      const repo = await addRepo({ url: check.normalizedUrl });
      onAdded(repo);
    } catch (err) {
      setError(err?.message || 'Could not add repository.');
    } finally {
      setSubmitting(false);
    }
  }

  return createPortal(
    <div className="modal-root">
      <div className="modal-backdrop" onClick={() => !submitting && onClose()} />
      <div
        className="card modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <div className="modal__header">
          <h2 id={titleId} className="modal__title">Add repository</h2>
          <button
            type="button"
            className="btn btn--small"
            onClick={onClose}
            disabled={submitting}
            aria-label="Close modal"
          >
            Close
          </button>
        </div>

        <form className="modal__form" onSubmit={handleSubmit} noValidate>
          <p className="muted modal__hint">
            Enter a public GitHub repository URL to scan its dependencies and generate an SBOM.
          </p>

          <div className="modal__field">
            <label htmlFor="repo-url-input">GitHub repository URL</label>
            <input
              ref={inputRef}
              id="repo-url-input"
              type="url"
              placeholder="https://github.com/owner/repo"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={submitting}
            />
          </div>

          {error && (
            <div className="modal__error" role="alert">
              {error}
            </div>
          )}

          <div className="modal__actions">
            <button type="button" className="btn" onClick={onClose} disabled={submitting}>
              Cancel
            </button>
            <button type="submit" className="btn btn--primary" disabled={submitting}>
              {submitting ? 'Adding...' : 'Add repository'}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  );
}
