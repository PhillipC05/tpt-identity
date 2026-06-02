package auth

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sort"
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
.btn{display:block;width:100%;padding:12px;border:none;border-radius:4px;font-size:1rem;cursor:pointer;font-weight:500;text-align:center;text-decoration:none}
.btn-primary{background:#1a73e8;color:#fff}
.btn-primary:hover{background:#1557b0}
.btn-secondary{background:#fff;color:#444;border:1px solid #ccc;margin-bottom:10px}
.btn-secondary:hover{background:#f8f8f8}
.or-sep{display:flex;align-items:center;gap:12px;margin:20px 0;color:#aaa;font-size:.85rem}
.or-sep::before,.or-sep::after{content:"";flex:1;height:1px;background:#e0e0e0}
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
<p>Choose how you would like to sign in.</p>
{{if .Error}}<div class="msg error">{{.Error}}</div>{{end}}
{{if .Providers}}
{{range .Providers}}<a href="{{.URL}}" class="btn btn-secondary">{{.DisplayName}}</a>{{end}}
<div class="or-sep">or</div>
{{end}}
<form method="POST" action="/auth/magic-link/request">
<input type="hidden" name="next" value="{{.Next}}">
<label for="email">Email address</label>
<input type="email" id="email" name="email" placeholder="you@example.com" required autofocus>
<button type="submit" class="btn btn-primary">Send sign-in link</button>
</form>
{{end}}
</div>
</body>
</html>`))

type providerButton struct {
	Name        string
	DisplayName string
	URL         string
}

type loginData struct {
	Next      string
	Email     string
	Sent      bool
	Error     string
	Providers []providerButton
}

// Handler provides HTTP handlers for the embedded login flow.
type Handler struct {
	ml      *providers.MagicLinkBridge
	oidcRPs map[string]*providers.OIDCRPBridge // keyed by name; nil map = feature disabled
	mapper  *bridge.Mapper
	sender  *Sender
	oidc    *oidc.Provider
	issuer  string
}

// New creates a login Handler. oidcRPs may be nil or empty to disable external IdP sign-in.
func New(
	ml *providers.MagicLinkBridge,
	oidcRPs map[string]*providers.OIDCRPBridge,
	mapper *bridge.Mapper,
	sender *Sender,
	oidcProv *oidc.Provider,
	issuer string,
) *Handler {
	return &Handler{ml: ml, oidcRPs: oidcRPs, mapper: mapper, sender: sender, oidc: oidcProv, issuer: issuer}
}

// LoginPage handles GET /auth/login.
func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTmpl.Execute(w, loginData{Next: next, Providers: h.providerButtons(next)})
}

// RequestMagicLink handles POST /auth/magic-link/request.
func (h *Handler) RequestMagicLink(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	next := r.FormValue("next")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if email == "" {
		loginTmpl.Execute(w, loginData{Next: next, Error: "Please enter your email address.", Providers: h.providerButtons(next)})
		return
	}

	rawToken, _, err := h.ml.GenerateToken(r.Context(), email)
	if err != nil {
		loginTmpl.Execute(w, loginData{Next: next, Email: email, Error: "Something went wrong. Please try again.", Providers: h.providerButtons(next)})
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
func (h *Handler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rawToken := q.Get("token")
	next := q.Get("next")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if rawToken == "" {
		h.renderError(w, "Missing sign-in token.")
		return
	}

	ext, err := h.ml.VerifyToken(r.Context(), rawToken)
	if err != nil {
		h.renderError(w, "This sign-in link is invalid or has expired. Please request a new one.")
		return
	}

	subjectDID, _, err := h.mapper.FindOrCreate(r.Context(), ext)
	if err != nil {
		h.renderError(w, "Unable to resolve your identity. Please try again.")
		return
	}

	h.completeAuth(w, r, subjectDID, next)
}

// OIDCStart handles GET /auth/oidc/{provider}/start — redirects to the external IdP.
func (h *Handler) OIDCStart(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	rp, ok := h.oidcRPs[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	next := r.URL.Query().Get("next")
	if err := rp.StartFlow(w, r, next); err != nil {
		h.renderError(w, "Unable to start sign-in. Please try again.")
	}
}

// OIDCCallback handles GET /auth/oidc/{provider}/callback — receives the code from the IdP.
func (h *Handler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	rp, ok := h.oidcRPs[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	ext, next, err := rp.HandleCallback(r.Context(), r)
	if err != nil {
		h.renderError(w, "Sign-in failed. Please try again.")
		return
	}

	subjectDID, _, err := h.mapper.FindOrCreate(r.Context(), ext)
	if err != nil {
		h.renderError(w, "Unable to resolve your identity. Please try again.")
		return
	}

	h.completeAuth(w, r, subjectDID, next)
}

// completeAuth issues an OIDC code and redirects to the redirect_uri, or shows a
// success page if no OIDC flow was in progress.
func (h *Handler) completeAuth(w http.ResponseWriter, r *http.Request, subjectDID, next string) {
	if next == "" {
		fmt.Fprint(w, `<!DOCTYPE html><html lang="en"><head><title>Signed in</title></head><body><p>You are signed in. You may close this window.</p></body></html>`)
		return
	}

	nextURL, err := url.Parse(next)
	if err != nil {
		h.renderError(w, "Invalid redirect. Please start the sign-in process again.")
		return
	}
	nq := nextURL.Query()

	code, err := h.oidc.IssueCode(
		r.Context(),
		subjectDID,
		nq.Get("client_id"),
		nq.Get("redirect_uri"),
		nq.Get("scope"),
		nq.Get("nonce"),
		nq.Get("code_challenge"),
		nq.Get("code_challenge_method"),
		r.UserAgent(),
		remoteAddr(r),
	)
	if err != nil {
		h.renderError(w, "Unable to complete sign-in. Please start the process again.")
		return
	}

	finalURL := nq.Get("redirect_uri") + "?code=" + url.QueryEscape(code)
	if state := nq.Get("state"); state != "" {
		finalURL += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, finalURL, http.StatusFound)
}

func (h *Handler) renderError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	loginTmpl.Execute(w, loginData{Error: msg, Providers: h.providerButtons("")})
}

func (h *Handler) providerButtons(next string) []providerButton {
	if len(h.oidcRPs) == 0 {
		return nil
	}
	buttons := make([]providerButton, 0, len(h.oidcRPs))
	for name, rp := range h.oidcRPs {
		startURL := "/auth/oidc/" + name + "/start"
		if next != "" {
			startURL += "?next=" + url.QueryEscape(next)
		}
		buttons = append(buttons, providerButton{
			Name:        name,
			DisplayName: rp.DisplayName(),
			URL:         startURL,
		})
	}
	sort.Slice(buttons, func(i, j int) bool { return buttons[i].Name < buttons[j].Name })
	return buttons
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

// contextKey is used to pass the verified external identity through context (unused externally).
type contextKey int

const identityKey contextKey = iota

// WithIdentity stores a verified external identity in the context (for testing/extension).
func WithIdentity(ctx context.Context, ext *bridge.ExternalIdentity) context.Context {
	return context.WithValue(ctx, identityKey, ext)
}
