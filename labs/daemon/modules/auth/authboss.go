// Package auth provides modular authorization session state management.
//
// Ported from authboss-master — a modular authentication library for Go web applications.
// Implements session state events, token expiration checks, and middleware guards
// for the LumiNet local dashboard.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Session key constants used by the auth system.
const (
	// SessionKeyUID is the primary session key storing the user identifier.
	SessionKeyUID = "uid"
	// SessionKeyHalfAuth marks sessions authenticated via remember-me tokens
	// but requiring full re-authentication for sensitive operations.
	SessionKeyHalfAuth = "halfauth"
	// SessionKeyLastAction records the timestamp of the user's last action
	// for idle session expiration checks.
	SessionKeyLastAction = "last_action"
	// Session2FA is set when the user has completed two-factor authentication.
	Session2FA = "twofactor"
	// Session2FAAuthed is "true" after a 2FA challenge token has been verified.
	Session2FAAuthed = "twofactor_authed"
	// SessionOAuth2State holds the XSRF protection nonce for OAuth2 flows.
	SessionOAuth2State = "oauth2_state"
	// CookieRemember is the remember-me cookie/form-field name.
	CookieRemember = "rm"
	// FlashSuccessKey holds pending success flash messages.
	FlashSuccessKey = "flash_success"
	// FlashErrorKey holds pending error flash messages.
	FlashErrorKey = "flash_error"
)

// ErrUserNotFound is returned when the session does not contain a user ID.
var ErrUserNotFound = errors.New("auth: user not found in session")

// ErrTokenExpired is returned when a session token has exceeded its TTL.
var ErrTokenExpired = errors.New("auth: session token has expired")

// Event describes an auth lifecycle event type.
type Event int

const (
	EventRegister Event = iota
	EventLogin
	EventLoginFail
	EventLogout
	EventTwoFactorAdded
	EventTwoFactorRemoved
	EventRecoverStart
	EventRecoverEnd
)

// EventHandler processes an auth lifecycle event.
// w may be nil if the request has already been fully handled upstream.
type EventHandler func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error)

// Events is a registry of before/after lifecycle handlers for auth events.
type Events struct {
	mu     sync.RWMutex
	before map[Event][]EventHandler
	after  map[Event][]EventHandler
}

// NewEvents creates an empty event registry.
func NewEvents() *Events {
	return &Events{
		before: make(map[Event][]EventHandler),
		after:  make(map[Event][]EventHandler),
	}
}

// Before registers a handler to run before the given event.
func (e *Events) Before(ev Event, f EventHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.before[ev] = append(e.before[ev], f)
}

// After registers a handler to run after the given event.
func (e *Events) After(ev Event, f EventHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.after[ev] = append(e.after[ev], f)
}

// FireBefore runs all handlers registered to fire before the event.
func (e *Events) FireBefore(ev Event, w http.ResponseWriter, r *http.Request) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return callHandlers(e.before[ev], w, r)
}

// FireAfter runs all handlers registered to fire after the event.
func (e *Events) FireAfter(ev Event, w http.ResponseWriter, r *http.Request) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return callHandlers(e.after[ev], w, r)
}

func callHandlers(handlers []EventHandler, w http.ResponseWriter, r *http.Request) (bool, error) {
	handled := false
	for _, fn := range handlers {
		interrupt, err := fn(w, r, handled)
		if err != nil {
			return false, err
		}
		if interrupt {
			handled = true
		}
	}
	return handled, nil
}

// SessionToken represents an authenticated user session token with expiry tracking.
type SessionToken struct {
	UserID    string
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IsExpired returns true if the token has passed its expiration time.
func (st *SessionToken) IsExpired() bool {
	return time.Now().After(st.ExpiresAt)
}

// SessionManager manages in-memory session tokens with TTL expiration.
type SessionManager struct {
	mu     sync.RWMutex
	tokens map[string]*SessionToken // keyed by token string
	ttl    time.Duration
}

// NewSessionManager creates a session manager with the given token TTL.
func NewSessionManager(ttl time.Duration) *SessionManager {
	sm := &SessionManager{
		tokens: make(map[string]*SessionToken),
		ttl:    ttl,
	}
	return sm
}

// IssueToken creates and stores a new session token for the given user ID.
func (sm *SessionManager) IssueToken(userID string, token string) *SessionToken {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now()
	st := &SessionToken{
		UserID:    userID,
		Token:     token,
		IssuedAt:  now,
		ExpiresAt: now.Add(sm.ttl),
	}
	sm.tokens[token] = st
	return st
}

// ValidateToken checks whether a token exists and has not expired.
// Returns the session token on success or an error.
func (sm *SessionManager) ValidateToken(token string) (*SessionToken, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	st, ok := sm.tokens[token]
	if !ok {
		return nil, ErrUserNotFound
	}
	if st.IsExpired() {
		return nil, ErrTokenExpired
	}
	return st, nil
}

// RevokeToken removes a token from the session store.
func (sm *SessionManager) RevokeToken(token string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.tokens, token)
}

// PurgeExpired removes all expired tokens from the session store.
func (sm *SessionManager) PurgeExpired() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	count := 0
	for k, st := range sm.tokens {
		if st.IsExpired() {
			delete(sm.tokens, k)
			count++
		}
	}
	return count
}

// AuthMiddleware is an HTTP middleware that validates the Authorization bearer
// token against the SessionManager and stores the session context in the request.
type AuthMiddleware struct {
	sessions *SessionManager
}

// NewAuthMiddleware creates an AuthMiddleware backed by the given SessionManager.
func NewAuthMiddleware(sessions *SessionManager) *AuthMiddleware {
	return &AuthMiddleware{sessions: sessions}
}

type contextKey string

const sessionTokenCtxKey contextKey = "auth.session_token"

// Wrap returns an http.Handler that validates bearer tokens before calling next.
func (am *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		st, err := am.sessions.ValidateToken(token)
		if err != nil {
			if errors.Is(err, ErrTokenExpired) {
				http.Error(w, "Token expired", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), sessionTokenCtxKey, st)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SessionFromContext retrieves the SessionToken from a request context.
func SessionFromContext(ctx context.Context) (*SessionToken, error) {
	st, ok := ctx.Value(sessionTokenCtxKey).(*SessionToken)
	if !ok || st == nil {
		return nil, ErrUserNotFound
	}
	return st, nil
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		return auth[len(prefix):]
	}
	return ""
}

// IsFullyAuthed returns true if the request session is fully authenticated
// (not a half-auth remember-me session).
func IsFullyAuthed(r *http.Request) bool {
	v := r.Header.Get("X-Auth-Level")
	return v != "half"
}

// IsTwoFactored returns true if the session has 2FA verification on record.
func IsTwoFactored(r *http.Request) bool {
	v := r.Header.Get("X-2FA-Status")
	return v == "verified"
}

// RequirementType is a bit-set controlling Middleware access requirements.
type RequirementType int

const (
	RequireNone     RequirementType = 0x00
	RequireFullAuth RequirementType = 0x01
	Require2FA      RequirementType = 0x02
)

// FailureResponse controls how the Middleware responds to unauthorized requests.
type FailureResponse int

const (
	RespondUnauthorized FailureResponse = iota
	RespondNotFound
	RespondRedirectToLogin
)

// Guard creates an HTTP middleware that enforces auth requirements.
func Guard(sessions *SessionManager, reqs RequirementType, failureResp FailureResponse) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				respondWithFailure(w, r, failureResp)
				return
			}

			st, err := sessions.ValidateToken(token)
			if err != nil {
				respondWithFailure(w, r, failureResp)
				return
			}

			if reqs&RequireFullAuth != 0 && !IsFullyAuthed(r) {
				respondWithFailure(w, r, failureResp)
				return
			}
			if reqs&Require2FA != 0 && !IsTwoFactored(r) {
				respondWithFailure(w, r, failureResp)
				return
			}

			ctx := context.WithValue(r.Context(), sessionTokenCtxKey, st)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func respondWithFailure(w http.ResponseWriter, r *http.Request, resp FailureResponse) {
	switch resp {
	case RespondNotFound:
		http.NotFound(w, r)
	case RespondRedirectToLogin:
		http.Redirect(w, r, fmt.Sprintf("/login?redirect=%s", r.URL.Path), http.StatusTemporaryRedirect)
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}
