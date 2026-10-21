/* Cognito hosted-UI auth helper (implicit/token flow).
 *
 * Flow:
 *   - signIn() -> redirect to the Cognito hosted UI.
 *   - On return, the id_token arrives in the URL fragment (#id_token=...).
 *     captureTokenFromHash() parses & stores it (sessionStorage) and cleans the URL.
 *   - getIdToken() returns a valid (unexpired) token or null.
 *   - authHeader() -> { Authorization: "Bearer <token>" } for API calls.
 *   - currentUser() -> email/username from the token claims (used as approver).
 *
 * No external SDK; pure browser JS so the static site stays dependency-free.
 */
(function () {
  const cfg = (window.APP_CONFIG && window.APP_CONFIG.COGNITO) || {};
  const KEY = "vr_id_token";

  function hostedBase() {
    return `https://${cfg.domain}.auth.${cfg.region}.amazoncognito.com`;
  }

  function authConfigured() {
    return !!(cfg.domain && cfg.region && cfg.clientId && cfg.redirectUri);
  }

  function signIn() {
    if (!authConfigured()) return;
    const url = `${hostedBase()}/login?client_id=${encodeURIComponent(cfg.clientId)}` +
      `&response_type=token&scope=openid+email+profile` +
      `&redirect_uri=${encodeURIComponent(cfg.redirectUri)}`;
    window.location.assign(url);
  }

  function signOut() {
    sessionStorage.removeItem(KEY);
    if (!authConfigured()) { window.location.reload(); return; }
    const url = `${hostedBase()}/logout?client_id=${encodeURIComponent(cfg.clientId)}` +
      `&logout_uri=${encodeURIComponent(cfg.redirectUri)}`;
    window.location.assign(url);
  }

  function _decode(token) {
    try {
      const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(decodeURIComponent(escape(atob(payload))));
    } catch (e) { return null; }
  }

  function captureTokenFromHash() {
    if (!window.location.hash) return;
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token = params.get("id_token");
    if (token) {
      sessionStorage.setItem(KEY, token);
      // clean the token out of the URL
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }

  function getIdToken() {
    const token = sessionStorage.getItem(KEY);
    if (!token) return null;
    const claims = _decode(token);
    if (!claims || (claims.exp && claims.exp * 1000 < Date.now())) {
      sessionStorage.removeItem(KEY);
      return null;
    }
    return token;
  }

  function authHeader() {
    const t = getIdToken();
    return t ? { Authorization: "Bearer " + t } : {};
  }

  function currentUser() {
    const t = getIdToken();
    const c = t ? _decode(t) : null;
    return c ? (c.email || c["cognito:username"] || c.sub) : null;
  }

  window.AUTH = {
    authConfigured, signIn, signOut, captureTokenFromHash,
    getIdToken, authHeader, currentUser,
  };

  // capture a token on load if we just returned from the hosted UI
  captureTokenFromHash();
})();
