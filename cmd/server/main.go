package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"payment-backend/internal/httpserver"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	port := os.Getenv("PORT")
	if port == "" {
		port = "5003"
	}

	h := httpserver.New()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/create-payment", h.CreatePayment)

	// register callback & result endpoints
	// wrap the callback with requestLogger to log incoming body and headers
	mux.HandleFunc("/api/payment/callback", requestLogger(h.PaymentCallback))
	mux.HandleFunc("/api/payment/result", h.PaymentResult)

	// Wrap mux with CORS middleware
	handler := corsMiddleware(mux)

	log.Printf("Go backend listening on :%s", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

// corsMiddleware returns a handler that applies CORS rules based on ENVIRONMENT env var.
// If ENVIRONMENT == "Production" -> allow origins from go.dorira.com
// Otherwise (development) -> allow any origin (for easier local testing).
func corsMiddleware(next http.Handler) http.Handler {
	env := strings.TrimSpace(os.Getenv("ENVIRONMENT"))
	prod := strings.EqualFold(env, "Production")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := false

		if origin != "" {
			// Parse origin to get hostname (works for "http(s)://host:port")
			if u, err := url.Parse(origin); err == nil && u.Host != "" {
				// In production allow only go.dorira.com; in development allow any origin
				if prod {
					if strings.EqualFold(u.Hostname(), "go.dorira.com") {
						allowed = true
					}
				} else {
					allowed = true
				}
			}
		}

		// If allowed, mirror the origin (recommended) and set CORS headers.
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			// Allowed methods and headers: expand if needed.
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			// If you need cookies/auth to be sent, set this to "true" and ensure frontend uses credentials.
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight requests quickly.
		if r.Method == http.MethodOptions {
			// If origin was present but not allowed, return 403
			if origin != "" && !allowed {
				http.Error(w, "Origin not allowed", http.StatusForbidden)
				return
			}
			// Return 204 No Content for allowed OPTIONS
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Continue to actual handler
		next.ServeHTTP(w, r)
	})
}

// requestLogger logs essential request info and the request body.
// It restores r.Body so the next handler can read it as usual.
// NOTE: reading the full body into memory may be problematic for very large requests.
// If you expect huge bodies, replace with a streaming/limited approach.
func requestLogger(next http.HandlerFunc) http.HandlerFunc {
	const maxLogBody = 1 << 20 // 1 MiB preview for logs

	return func(w http.ResponseWriter, r *http.Request) {
		// basic request info
		log.Printf("[REQUEST] %s %s from %s", r.Method, r.URL.String(), r.RemoteAddr)

		// useful headers (avoid logging Authorization)
		if origin := r.Header.Get("Origin"); origin != "" {
			log.Printf("  Origin: %s", origin)
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			log.Printf("  Content-Type: %s", ct)
		}

		// read full body (be mindful of size). We'll log only a preview up to maxLogBody.
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("  warning: failed reading request body for logging: %v", err)
			// ensure r.Body is non-nil for next handler
			r.Body = io.NopCloser(bytes.NewReader(nil))
			next(w, r)
			return
		}

		// restore the body so next handler can read it
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// log preview or full body
		if len(bodyBytes) == 0 {
			log.Printf("  Body: <empty>")
		} else if len(bodyBytes) <= maxLogBody {
			log.Printf("  Original Body (%d bytes):\n%s", len(bodyBytes), string(bodyBytes))
		} else {
			log.Printf("  Originall Body (truncated preview %d bytes of %d):\n%s", maxLogBody, len(bodyBytes), string(bodyBytes[:maxLogBody]))
		}

		next(w, r)
	}
}
