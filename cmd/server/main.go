package main

import (
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
	mux.HandleFunc("/api/payment/callback", h.PaymentCallback)
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
// Otherwise -> allow localhost (any port) and 127.0.0.1 (any port)
func corsMiddleware(next http.Handler) http.Handler {
	env := strings.TrimSpace(os.Getenv("ENVIRONMENT"))
	prod := strings.EqualFold(env, "Production")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := false

		if origin != "" {
			// Parse origin to get hostname (works for "http(s)://host:port")
			if u, err := url.Parse(origin); err == nil && u.Host != "" {
				//host := u.Hostname() // strip port if present
				if prod {
					//if strings.EqualFold(host, "go.dorira.com") {

					allowed = true
					//	}
				} else {
					// development: allow localhost and 127.0.0.1 (any port)
					//if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "127.0.0.1") || strings.EqualFold(host, "*"){
					allowed = true
					//}
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
