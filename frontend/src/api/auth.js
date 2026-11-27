import { request, getToken, USE_FAKE_API } from './client.js';

const TOKEN_KEY = 'sb_token';
const fake = () => import('./fake/portal.js');

/**
 * Normalize a user object from the backend.
 * Backend currently omits `role`, so default to 'analyst' to keep UI actions usable.
 */
export function normalizeUser(raw) {
  if (!raw || typeof raw !== 'object') return raw;
  return {
    ...raw,
    id: String(raw.id ?? raw._id ?? ''),
    role: raw.role || 'analyst',
  };
}

/** Save the JWT token safely (some browsers block localStorage in strict mode). */
export function saveToken(token) {
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* ignore storage write errors */
  }
}

/** Remove the stored JWT token on sign-out. */
export function clearToken() {
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore storage remove errors */
  }
}

/**
 * Sign in with email and password.
 * Stores the returned token so future requests via client.js include Authorization: Bearer <token>.
 */
export async function login({ email, password }) {
  const payload = { email: String(email || '').trim(), password: String(password || '') };
  const data = USE_FAKE_API
    ? await (await fake()).login(payload)
    : await request('/auth/login', { method: 'POST', body: payload });

  if (data?.token) saveToken(data.token);
  return { ...data, user: normalizeUser(data?.user) };
}

/**
 * Create a new account and sign in immediately.
 */
export async function register({ name, email, password }) {
  const payload = {
    name: String(name || '').trim(),
    email: String(email || '').trim(),
    password: String(password || ''),
  };
  const data = USE_FAKE_API
    ? await (await fake()).register(payload)
    : await request('/auth/register', { method: 'POST', body: payload });

  if (data?.token) saveToken(data.token);
  return { ...data, user: normalizeUser(data?.user) };
}

/**
 * Restore the currently signed-in user from the saved token.
 * Returns null if no token is present so the app can show the login page cleanly.
 */
export async function getMe() {
  if (!getToken()) return null;
  if (USE_FAKE_API) return normalizeUser(await (await fake()).getMe());
  const data = await request('/auth/me');
  return normalizeUser(data?.user || data);
}

/** Clear local session state. */
export function logout() {
  clearToken();
}
