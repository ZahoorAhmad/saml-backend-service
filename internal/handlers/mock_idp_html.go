package handlers

import "fmt"

const mockIdPStyles = `
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  color: #e2e8f0;
  -webkit-font-smoothing: antialiased;
}
.card {
  width: 100%;
  max-width: 28rem;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 0.75rem;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  padding: 2rem;
}
.badge {
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: #67e8f9;
  background: rgba(6, 182, 212, 0.15);
  border: 1px solid rgba(6, 182, 212, 0.3);
  border-radius: 9999px;
  padding: 0.25rem 0.75rem;
  margin-bottom: 1rem;
}
h1 {
  font-size: 1.5rem;
  font-weight: 700;
  color: #f8fafc;
  margin-bottom: 0.5rem;
  line-height: 1.3;
}
.subtitle {
  font-size: 0.875rem;
  color: #94a3b8;
  margin-bottom: 1.75rem;
  line-height: 1.5;
}
form { display: flex; flex-direction: column; gap: 1.25rem; }
.field label {
  display: block;
  font-size: 0.8125rem;
  font-weight: 500;
  color: #cbd5e1;
  margin-bottom: 0.375rem;
}
.field input {
  width: 100%;
  background: #0f172a;
  border: 1px solid #475569;
  border-radius: 0.5rem;
  padding: 0.625rem 0.75rem;
  font-size: 0.875rem;
  color: #f1f5f9;
  outline: none;
  transition: border-color 0.15s, box-shadow 0.15s;
}
.field input:focus {
  border-color: #06b6d4;
  box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.2);
}
button[type="submit"] {
  margin-top: 0.5rem;
  width: 100%;
  padding: 0.75rem 1rem;
  font-size: 0.9375rem;
  font-weight: 600;
  color: #fff;
  background: #0891b2;
  border: none;
  border-radius: 0.5rem;
  cursor: pointer;
  transition: background 0.15s;
}
button[type="submit"]:hover { background: #06b6d4; }
button[type="submit"]:active { background: #0e7490; }
.footer {
  margin-top: 1.5rem;
  padding-top: 1.25rem;
  border-top: 1px solid #334155;
  font-size: 0.75rem;
  color: #64748b;
  text-align: center;
}
.loading {
  text-align: center;
  padding: 2rem 0;
}
.spinner {
  width: 2.5rem;
  height: 2.5rem;
  border: 3px solid #334155;
  border-top-color: #06b6d4;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  margin: 0 auto 1rem;
}
@keyframes spin { to { transform: rotate(360deg); } }
`

func renderMockIdPLoginPage(tenantID string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mock IdP — %s</title>
  <style>%s</style>
</head>
<body>
  <div class="card">
    <span class="badge">Development Only</span>
    <h1>Mock SAML IdP</h1>
    <p class="subtitle">Sign in to workspace <strong>%s</strong>. This page simulates your organization's identity provider for local testing.</p>
    <form method="POST">
      <div class="field">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" value="user@%s" required />
      </div>
      <div class="field">
        <label for="roles">Roles</label>
        <input id="roles" name="roles" type="text" value="cashier,admin" required />
      </div>
      <button type="submit">Sign in</button>
    </form>
    <p class="footer">saml-backend-service · mock IdP endpoint</p>
  </div>
</body>
</html>`, xmlEscape(tenantID), mockIdPStyles, xmlEscape(tenantID), xmlEscape(tenantID))
}

func renderMockIdPAutoPostPage(acsURL, encodedResponse, relayState string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Redirecting…</title>
  <style>%s</style>
</head>
<body onload="document.forms[0].submit()">
  <div class="card">
    <div class="loading">
      <div class="spinner"></div>
      <p>Completing SAML sign-in…</p>
    </div>
    <form method="POST" action="%s">
      <input type="hidden" name="SAMLResponse" value="%s" />
      <input type="hidden" name="RelayState" value="%s" />
      <noscript>
        <p style="text-align:center;margin-top:1rem;">
          <button type="submit">Continue</button>
        </p>
      </noscript>
    </form>
  </div>
</body>
</html>`, mockIdPStyles, acsURL, encodedResponse, xmlEscape(relayState))
}
