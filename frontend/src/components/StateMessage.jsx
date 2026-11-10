/** Loading / error / empty placeholders shared by the drawer and the SBOM tab. */
export function Loading({ label = 'Loading...' }) {
  return (
    <div className="state-box" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorState({ title = 'Something went wrong', message, onRetry }) {
  return (
    <div className="state-box state-box--error" role="alert">
      <strong>{title}</strong>
      {message ? <p>{message}</p> : null}
      {onRetry ? (
        <button type="button" className="btn" onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

export function EmptyState({ title, message }) {
  return (
    <div className="state-box">
      <strong>{title}</strong>
      {message ? <p>{message}</p> : null}
    </div>
  );
}
