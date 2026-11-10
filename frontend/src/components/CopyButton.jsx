import { useEffect, useRef, useState } from 'react';

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

export default function CopyButton({ text, label = 'Copy' }) {
  const [state, setState] = useState('idle'); // idle | copied | failed
  const timer = useRef(null);
  useEffect(() => () => clearTimeout(timer.current), []);

  async function onClick() {
    const ok = await copyText(text);
    setState(ok ? 'copied' : 'failed');
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState('idle'), 2000);
  }

  return (
    <>
      <button type="button" className="btn btn--small" onClick={onClick} aria-label={`${label}: ${text}`}>
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}
      </button>
      <span className="sr-only" role="status">
        {state === 'copied' ? 'Copied to clipboard' : state === 'failed' ? 'Copy failed' : ''}
      </span>
    </>
  );
}
