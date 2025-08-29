package httpserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"payment-backend/internal/sdk"
)

// Server holds config and an in-memory store for callback results.
type Server struct {
	merchantID     string
	merchantKeyB64 string
	gatewayURL     string
	sdk            *sdk.PaymentSDK

	// in-memory store for decrypted callback results keyed by orderNo
	store map[string]map[string]any
	mu    sync.RWMutex
}

// New constructs server using environment variables.
func New() *Server {
	merchantID := os.Getenv("MERCHANT_ID")
	merchantKeyB64 := os.Getenv("MERCHANT_KEY_BASE64")
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "https://uatcheckout.example.com/ms-transaction"
	}
	s := &Server{
		merchantID:     merchantID,
		merchantKeyB64: merchantKeyB64,
		gatewayURL:     gatewayURL,
		store:          make(map[string]map[string]any),
	}
	s.sdk = sdk.NewPaymentSDK(merchantID, merchantKeyB64, gatewayURL)
	return s
}

// CreatePayment handler accepts JSON BuildPayload and returns prepared HTML and fields.
type CreatePaymentRequest struct {
	// Expecting nested objects similar to SDK.BuildPayload
	Txn         map[string]any `json:"txn"`
	PgDetails   map[string]any `json:"pg_details"`
	CardDetails map[string]any `json:"card_details"`
	CustDetails map[string]any `json:"cust_details"`
	BillDetails map[string]any `json:"bill_details"`
	ShipDetails map[string]any `json:"ship_details"`
	ItemDetails map[string]any `json:"item_details"`
	UpiDetails  map[string]any `json:"upi_details"`
	Other       string         `json:"other"`
}

type CreatePaymentResponse struct {
	HTML            string `json:"html"`
	MerchantRequest string `json:"merchant_request"`
	Hash            string `json:"hash"`
	EncryptInput    string `json:"encrypt_input"`
	HashInput       string `json:"hash_input"`
	MerchantID      string `json:"merchant_id"`
}

func (s *Server) CreatePayment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req CreatePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	payload := sdk.BuildPayload{
		Txn:         req.Txn,
		PgDetails:   req.PgDetails,
		CardDetails: req.CardDetails,
		CustDetails: req.CustDetails,
		BillDetails: req.BillDetails,
		ShipDetails: req.ShipDetails,
		ItemDetails: req.ItemDetails,
		UpiDetails:  req.UpiDetails,
		Other:       req.Other,
	}

	result, err := s.sdk.PreparePayment(payload)
	if err != nil {
		log.Println("PreparePayment error:", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CreatePaymentResponse{
		HTML:            result.HTML,
		MerchantRequest: result.MerchantRequest,
		Hash:            result.Hash,
		EncryptInput:    result.EncryptInput,
		HashInput:       result.HashInput,
		MerchantID:      result.MerchantID,
	})
}

func (s *Server) PaymentCallback(w http.ResponseWriter, r *http.Request) {
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "https://go.dorira.com"
	}

	switch r.Method {
	case http.MethodPost:
		// parse both form and json
		inMap := map[string]string{}
		ct := r.Header.Get("Content-Type")

		if strings.HasPrefix(ct, "application/json") {
			var j map[string]any
			if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
				// fallback to parse form
				_ = r.ParseForm()
			} else {
				for k, v := range j {
					if v == nil {
						inMap[k] = ""
					} else {
						inMap[k] = fmt.Sprint(v)
					}
				}
			}
		} else {
			// parse form
			if err := r.ParseForm(); err == nil {
				for k := range r.PostForm {
					inMap[k] = r.PostForm.Get(k)
				}
			}
		}

		// attempt to decrypt fields using SDK helper
		decrypted, errs := s.sdk.DecryptCallbackMap(inMap)
		log.Printf("decrypted %+v", decrypted)

		// try to detect orderNo key (case-insensitive variants) from decrypted map
		orderNo := ""
		for k, v := range decrypted {
			if strings.EqualFold(k, "orderNo") || strings.EqualFold(k, "order_no") {
				if v != "" {
					orderNo = fmt.Sprint(v)
					break
				}
			}
		}
		// fallback to incoming map if not found
		if orderNo == "" {
			for k, v := range inMap {
				if strings.EqualFold(k, "orderNo") || strings.EqualFold(k, "order_no") {
					if v != "" {
						orderNo = v
						break
					}
				}
			}
		}

		// store decrypted payload (and timestamp)
		if orderNo == "" {
			// try transactionId as key
			if v, ok := decrypted["transactionId"]; ok && v != "" {
				orderNo = fmt.Sprint(v)
			}
		}

		if orderNo == "" {
			// as last resort, generate key with timestamp
			orderNo = fmt.Sprintf("tmp-%d", time.Now().UnixNano())
		}

		// convert map[string]string to map[string]any for storage
		out := make(map[string]any)
		for k, v := range decrypted {
			out[k] = v
		}
		// add original (unencrypted) keys if absent
		for k, v := range inMap {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
		out["_received_at"] = time.Now().UTC().Format(time.RFC3339)
		out["_decrypt_errors"] = func() []string {
			es := []string{}
			for _, e := range errs {
				es = append(es, e.Error())
			}
			return es
		}()

		// store
		s.mu.Lock()
		s.store[orderNo] = out
		s.mu.Unlock()

		// Decide whether this POST looks like a browser redirect or a server callback.
		// Browser POSTs typically have Accept: text/html, a browser User-Agent, and/or a Referer.
		ua := strings.ToLower(r.Header.Get("User-Agent"))
		accept := strings.ToLower(r.Header.Get("Accept"))
		referer := r.Header.Get("Referer")
		ctLower := strings.ToLower(ct)

		isBrowser := false
		if strings.Contains(accept, "text/html") {
			isBrowser = true
		} else if ua != "" && (strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") ||
			strings.Contains(ua, "safari") || strings.Contains(ua, "firefox") || strings.Contains(ua, "edge")) {
			// prefer form submissions for browser detection, but referer is also a strong sign
			if strings.Contains(ctLower, "application/x-www-form-urlencoded") || strings.Contains(ctLower, "multipart/form-data") {
				isBrowser = true
			} else if referer != "" {
				isBrowser = true
			}
		}

		// Debug log showing detection result
		log.Printf("isBrowserPost=%v orderNo=%s UA=%q Accept=%q Referer=%q Content-Type=%q", isBrowser, orderNo, r.Header.Get("User-Agent"), r.Header.Get("Accept"), referer, ct)

		// Build frontend target (frontend will poll /api/payment/result)
		target := strings.TrimRight(frontendURL, "/") + "/payment/result?orderNo=" + url.QueryEscape(orderNo)

		if isBrowser {
			// redirect the user's browser to frontend (so merchant UI can poll result)
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}

		// Otherwise this is a server-to-server callback: respond with JSON ack expected by PG.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "orderNo": orderNo})
		return

	case http.MethodGet:
		// browser redirect — accept several param names and redirect immediately to frontend
		q := r.URL.Query()

		// detect orderNo from many possible keys
		orderNo := firstNonEmpty(q.Get("orderNo"), q.Get("order_no"), q.Get("orderId"), q.Get("order_id"), q.Get("transactionId"), q.Get("transaction_id"))

		if orderNo == "" {
			// nothing to do; show a simple page
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<html><body><h3>Payment callback received</h3><p>No orderNo provided. If you were redirected here from the payment gateway, your browser should be forwarded to the merchant frontend shortly.</p></body></html>`))
			return
		}

		// Build frontend URL and redirect immediately (frontend will poll /api/payment/result)
		target := strings.TrimRight(frontendURL, "/") + "/api/payment/result?orderNo=" + url.QueryEscape(orderNo)
		http.Redirect(w, r, target, http.StatusSeeOther)
		return

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// return the first non-empty string from arguments
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// PaymentResult returns stored decrypted callback payload by orderNo as JSON.
func (s *Server) PaymentResult(w http.ResponseWriter, r *http.Request) {
	orderNo := r.URL.Query().Get("orderNo")
	if orderNo == "" {
		http.Error(w, "orderNo required", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	val, ok := s.store[orderNo]
	s.mu.RUnlock()
	if !ok {
		// not found => return empty JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(val)
}

// htmlEscape minimal replacement for safe embedding
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "\"", "&quot;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
