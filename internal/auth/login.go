package auth

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/PhillipC05/tpt-identity/internal/bridge"
	"github.com/PhillipC05/tpt-identity/internal/bridge/providers"
	"github.com/PhillipC05/tpt-identity/oidc"
)

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — TPT Identity</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.12);padding:40px;width:100%;max-width:400px}
h1{font-size:1.5rem;margin-bottom:8px}
p{color:#555;margin-bottom:24px;line-height:1.5}
label{display:block;font-weight:500;margin-bottom:6px;font-size:.9rem}
input[type=email]{width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:4px;font-size:1rem;margin-bottom:16px}
input[type=email]:focus{outline:none;border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.2)}
button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:1rem;cursor:pointer;font-weight:500}
button:hover{background:#1557b0}
.msg{padding:12px 16px;border-radius:4px;margin-bottom:16px;line-height:1.5}
.success{background:#e8f5e9;color:#1b5e20;border-left:4px solid #4caf50}
.error{background:#ffebee;color:#b71c1c;border-left:4px solid #f44336}
</style>
</head>
<body>
<div class="card">
<h1>Sign in</h1>
{{if .Sent}}
<div class="msg success">A sign-in link has been sent to <strong>{{.Email}}</strong>. Check your inbox and click the link to continue.</div>
{{else}}
<p>Enter your email address. We will send you a sign-in link — no password needed.</p>
{{if .Error}}<div class="msg error">{{.Error}}</div>{{end}}
<form method="POST" action="/auth/magic-link/request">
<input type="hidden" name="next" value="{{.Next}}">
<label for="email">Email address</label>
<input type="email" id="email" name="email" placeholder="you@example.com" required autofocus>
<button type="submit">Send sign-in link</button>
</form>
{{end}}
</div>
</body>
</html>`))

type loginData struct {
	Next  string
	Email string
	Sent  bool
	Error string
}

// Handler provides HTTP handlers for the embedded magic-link login flow.
type Handler struct {
	ml     *providers.MagicLinkBridge
	mapper *bridge.Mapper
	sender *Sender
	oidc   *oidc.Provider
	issuer string
}

// New creates a login Handler.
func New(ml *providers.MagicLinkBridge, mapper *bridge.Mapper, sender *Sender, oidcProv *oidc.Provider, issuer string) *Handler {
	return &Handler{ml: ml, mapper: mapper, sender: sender, oidc: oidcProv, issuer: issuer}
}

// LoginPage handles GET /auth/login — serves the email input form.
func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTmpl.Execute(w, loginData{Next: next})
}

// RequestMagicLink handles POST /auth/magic-link/request.
// Stores a one-time token and sends the magic link email.
func (h *Handler) RequestMagicLink(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	next := r.FormValue("next")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if email == "" {
		loginTmpl.Execute(w, loginData{Next: next, Error: "Please enter your email address."})
		return
	}

	rawToken, _, err := h.ml.GenerateToken(r.Context(), email)
	if err != nil {
		loginTmpl.Execute(w, loginData{Next: next, Email: email, Error: "Something went wrong. Please try again."})
		return
	}

	verifyURL := h.issuer + "/auth/magic-link/verify?token=" + url.QueryEscape(rawToken)
	if next != "" {
		verifyURL += "&next=" + url.QueryEscape(next)
	}

	// Ignore send errors to prevent email enumeration; sender logs failures.
	_ = h.sender.SendMagicLink(email, verifyURL)

	loginTmpl.Execute(w, loginData{Next: next, Email: email, Sent: true})
}

// VerifyMagicLink handles GET /auth/magic-link/verify.
// Validates the one-time token, resolves or creates the platform DID, issues an OIDC
// authorization code, and redirects to the original redirect_uri.
func (h *Handler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rawToken := q.Get("token")
	next := q.Get("next")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if rawToken == "" {
		h.verifyError(w, "Missing sign-in token.")
		return
	}

	// Verify the token (single-use — deleted on success).
	ext, err := h.ml.VerifyToken(r.Context(), rawToken)
	if err != nil {
		h.verifyError(w, "This sign-in link is invalid or has expired. Please request a new one.")
		return
	}

	// Resolve or create the platform DID for this email address.
	subjectDID, _, err := h.mapper.FindOrCreate(r.Context(), ext)
	if err != nil {
		h.verifyError(w, "Unable to resolve your identity. Please try again.")
		return
	}

	if next == "" {
		// Standalone sign-in (no OIDC flow in progress).
		fmt.Fprint(w, `<!DOCTYPE html><html lang="en"><head><title>Signed in</title></head><body><p>You are signed in. You may close this window.</p></body></html>`)
		return
	}

	// Parse the original /authorize URL to extract OIDC parameters.
	nextURL, err := url.Parse(next)
	if err != nil {
		h.verifyError(w, "Invalid redirect. Please start the sign-in process again.")
		return
	}
	nq := nextURL.Query()
	clientID := nq.Get("client_id")
	redirectURI := nq.Get("redirect_uri")
	scope := nq.Get("scope")
	nonce := nq.Get("nonce")
	state := nq.Get("state")
	codeChallenge := nq.Get("code_challenge")
	codeChallengeMethod := nq.Get("code_challenge_method")

	// Issue the OIDC authorization code (validates client + redirect_uri internally).
	code, err := h.oidc.IssueCode(
		r.Context(),
		subjectDID, clientID, redirectURI, scope, nonce,
		codeChallenge, codeChallengeMethod,
		r.UserAgent(), remoteAddr(r),
	)
	if err != nil {
		h.verifyError(w, "Unable to complete sign-in. Please start the process again.")
		return
	}

	finalURL := redirectURI + "?code=" + url.QueryEscape(code)
	if state != "" {
		finalURL += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, finalURL, http.StatusFound)
}

func (h *Handler) verifyError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	loginTmpl.Execute(w, loginData{Error: msg})
}

func remoteAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
