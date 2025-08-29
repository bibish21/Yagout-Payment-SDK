package sdk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Static IV for merchant_request encryption (matches PHP sample)
var staticIV = []byte("0123456789abcdef")

// Zero IV if needed
var zeroIV = make([]byte, 16)

type PaymentSDK struct {
	merchantID     string
	merchantKeyB64 string
	gatewayURL     string
	Debug          bool // enable debug logs and raw URL dump
}

func NewPaymentSDK(merchantID, keyB64, gateway string) *PaymentSDK {
	return &PaymentSDK{merchantID: merchantID, merchantKeyB64: keyB64, gatewayURL: gateway}
}

// Optional setter
func (p *PaymentSDK) SetDebug(d bool) { p.Debug = d }

type BuildPayload struct {
	Txn         map[string]any
	PgDetails   map[string]any
	CardDetails map[string]any
	CustDetails map[string]any
	BillDetails map[string]any
	ShipDetails map[string]any
	ItemDetails map[string]any
	UpiDetails  map[string]any
	Other       string
}

type PrepareResult struct {
	HTML            string
	MerchantRequest string
	Hash            string
	EncryptInput    string
	HashInput       string
	MerchantID      string
}

// --- helpers & validators ---

func getString(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// buildSection trims each value to avoid hidden whitespace characters
func buildSection(m map[string]any, keys []string) string {
	vals := make([]string, len(keys))
	for i, k := range keys {
		vals[i] = strings.TrimSpace(getString(m, k))
	}
	return strings.Join(vals, "|")
}

func trimTrailingEmptySections(sections []string) []string {
	out := append([]string(nil), sections...)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] == "" {
			out = out[:i]
			continue
		}
		break
	}
	return out
}

// PKCS7 pad
func padPKCS7(b []byte, blockSize int) []byte {
	padLen := blockSize - (len(b) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(b, pad...)
}

func encryptCBCBase64(plaintext []byte, keyB64 string, iv []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", fmt.Errorf("key base64 decode: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes after base64 decode, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := padPKCS7(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptCBCBase64 decodes base64 ciphertext and decrypts AES-256-CBC with provided iv.
// Returns plaintext bytes (unpadded) or error.
func decryptCBCBase64(cipherB64, keyB64 string, iv []byte) ([]byte, error) {
	// decode key
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("key base64 decode: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes after base64 decode, got %d", len(key))
	}

	// decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, fmt.Errorf("ciphertext base64 decode: %w", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length invalid or not multiple of block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	plainPadded := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plainPadded, ciphertext)

	plain, err := removePKCS7Padding(plainPadded, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("invalid padding after decrypt: %w", err)
	}
	return plain, nil
}

// removePKCS7Padding validates and removes PKCS7 padding
func removePKCS7Padding(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	pad := int(b[len(b)-1])
	if pad < 1 || pad > blockSize {
		return nil, fmt.Errorf("invalid padding value %d", pad)
	}
	for i := 0; i < pad; i++ {
		if b[len(b)-1-i] != byte(pad) {
			return nil, errors.New("invalid PKCS7 padding bytes")
		}
	}
	return b[:len(b)-pad], nil
}

// --- regex validators (precompiled where helpful) ---

var (
	reAlphaExactMax  = func(n int) *regexp.Regexp { return regexp.MustCompile(fmt.Sprintf(`^[A-Za-z]{1,%d}$`, n)) }
	reAlphaOptMax    = func(n int) *regexp.Regexp { return regexp.MustCompile(fmt.Sprintf(`^[A-Za-z]{0,%d}$`, n)) }
	reNumExactMax    = func(n int) *regexp.Regexp { return regexp.MustCompile(fmt.Sprintf(`^[0-9]{1,%d}$`, n)) }
	reNumOptMax      = func(n int) *regexp.Regexp { return regexp.MustCompile(fmt.Sprintf(`^[0-9]{0,%d}$`, n)) }
	reAlnumExactMax  = func(n int) *regexp.Regexp { return regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9]{1,%d}$`, n)) }
	reAlnumOptMax    = func(n int) *regexp.Regexp { return regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9]{0,%d}$`, n)) }
	reAlnumExtOptMax = func(n int) *regexp.Regexp {
		return regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9@._/#(),\\-\\s]{0,%d}$`, n))
	}
	reMobileStart = regexp.MustCompile(`^(09|07)[0-9]{8,13}$`) // ensures total length 10-15
	reEmail       = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	reYN          = regexp.MustCompile(`^[YN]$`)
)

var reAmount = regexp.MustCompile(`^[0-9]{1,10}(\.[0-9]{1,2})?$`)
var reMobileET = regexp.MustCompile(`^(09|07)[0-9]{8,13}$`)

// --- sanitizer & url validator ---

// sanitizeURLString removes BOM, zero-width, and control chars (except printable ones).
func sanitizeURLString(s string) string {
	s = strings.TrimSpace(s)
	// Remove BOM if present
	if strings.HasPrefix(s, "\uFEFF") {
		s = strings.TrimPrefix(s, "\uFEFF")
	}
	var b strings.Builder
	for _, r := range s {
		// drop zero-width marks and BOM
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
			continue
		}
		// keep printable runes >= space and not control
		if r >= 0x20 && !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func validateURLCandidate(raw string, maxLen int) error {
	s := sanitizeURLString(raw)
	if s == "" {
		return nil // caller handles required-ness
	}
	if len(s) > maxLen {
		return fmt.Errorf("url too long (max %d)", maxLen)
	}
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return fmt.Errorf("invalid URL parse: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("invalid URL scheme: %s", u.Scheme)
	}
	return nil
}

// debug helper — prints bytes and spaced hex for a string
func debugLogURL(label, raw string) {
	b := []byte(raw)
	log.Printf("%s (len=%d) bytes: %v\n", label, len(b), b)
	// spaced hex (easier to spot hidden bytes)
	hexParts := make([]string, 0, len(b))
	for i := 0; i < len(b); i++ {
		hexParts = append(hexParts, fmt.Sprintf("%02x", b[i]))
	}
	log.Printf("%s hex: %s\n", label, strings.Join(hexParts, " "))
}

// --- field validation functions ---

// Note: this one takes the SDK receiver so it can optionally log debug info.
func (p *PaymentSDK) validateTxnSection(m map[string]any) []string {
	errs := []string{}
	agID := strings.TrimSpace(getString(m, "ag_id"))
	meID := strings.TrimSpace(getString(m, "me_id"))
	orderNo := strings.TrimSpace(getString(m, "order_no"))
	amount := strings.TrimSpace(getString(m, "amount"))
	country := strings.TrimSpace(getString(m, "country"))
	currency := strings.TrimSpace(getString(m, "currency"))
	txnType := strings.TrimSpace(getString(m, "txn_type"))
	successURL := strings.TrimSpace(getString(m, "success_url"))
	failureURL := strings.TrimSpace(getString(m, "failure_url"))
	channel := strings.TrimSpace(getString(m, "channel"))

	if !reAlphaExactMax(11).MatchString(agID) {
		errs = append(errs, "ag_id: required, letters only, max 11")
	}
	if !reNumExactMax(20).MatchString(meID) {
		errs = append(errs, "me_id: required, digits only, max 20")
	}
	if !reAlnumExactMax(70).MatchString(orderNo) {
		errs = append(errs, "order_no: required, alphanumeric, max 70")
	}
	if !reAmount.MatchString(amount) {
		errs = append(errs, "amount: required, numeric, up to 10 digits and optional 1-2 decimals (e.g. 150.00)")
	}
	if !reAlnumExactMax(3).MatchString(country) {
		errs = append(errs, "country: required, alphanumeric, length 3")
	}
	if !reAlnumExactMax(3).MatchString(currency) {
		errs = append(errs, "currency: required, alphanumeric, length 3")
	}
	if txnType != "" && !reAlphaOptMax(10).MatchString(txnType) {
		errs = append(errs, "txn_type: letters only, max 10")
	}
	if successURL != "" {
		if e := validateURLCandidate(successURL, 200); e != nil {
			errs = append(errs, "success_url: invalid or too long (max 200): "+e.Error())
			if p.Debug {
				debugLogURL("success_url (raw)", getString(m, "success_url"))
			}
		}
	}
	if failureURL != "" {
		if e := validateURLCandidate(failureURL, 200); e != nil {
			log.Println("incoming failure url invalid:", failureURL, "->", e)
			errs = append(errs, "failure_url: invalid or too long (max 200): "+e.Error())
			if p.Debug {
				debugLogURL("failure_url (raw)", getString(m, "failure_url"))
			}
		}
	}
	if channel != "" && !reAlphaOptMax(10).MatchString(channel) {
		errs = append(errs, "channel: letters only, max 10")
	}
	return errs
}

func validatePgSection(m map[string]any) []string {
	errs := []string{}
	if v := strings.TrimSpace(getString(m, "pg_id")); v != "" {
		if !reNumOptMax(11).MatchString(v) {
			errs = append(errs, "pg_id: numeric, max 11")
		}
	}
	if v := strings.TrimSpace(getString(m, "paymode")); v != "" {
		if !reAlphaOptMax(100).MatchString(v) {
			errs = append(errs, "paymode: letters only")
		}
	}
	if v := strings.TrimSpace(getString(m, "scheme")); v != "" {
		if !reNumOptMax(11).MatchString(v) {
			errs = append(errs, "scheme: numeric, max 11")
		}
	}
	if v := strings.TrimSpace(getString(m, "wallet_type")); v != "" {
		if !reAlphaOptMax(100).MatchString(v) {
			errs = append(errs, "wallet_type: letters only")
		}
	}
	return errs
}

func validateCardSection(m map[string]any) []string {
	errs := []string{}
	if v := strings.TrimSpace(getString(m, "card_no")); v != "" {
		if !reNumOptMax(19).MatchString(v) {
			errs = append(errs, "card_no: numeric, max 19")
		}
	}
	if v := strings.TrimSpace(getString(m, "exp_month")); v != "" {
		if !regexp.MustCompile(`^(0[1-9]|1[0-2])$`).MatchString(v) {
			errs = append(errs, "exp_month: must be 01-12")
		}
	}
	if v := strings.TrimSpace(getString(m, "exp_year")); v != "" {
		if !regexp.MustCompile(`^[0-9]{4}$`).MatchString(v) {
			errs = append(errs, "exp_year: numeric, 4 digits")
		}
	}
	if v := strings.TrimSpace(getString(m, "cvv")); v != "" {
		if !regexp.MustCompile(`^[0-9]{3}$`).MatchString(v) {
			errs = append(errs, "cvv: numeric, 3 digits")
		}
	}
	if v := strings.TrimSpace(getString(m, "card_name")); v != "" {
		if !reAlphaOptMax(50).MatchString(v) {
			errs = append(errs, "card_name: letters only, max 50")
		}
	}
	return errs
}

func validateCustSection(m map[string]any) []string {
	errs := []string{}
	if v := strings.TrimSpace(getString(m, "cust_name")); v != "" {
		if !reAlphaOptMax(50).MatchString(v) {
			errs = append(errs, "cust_name: letters only, max 50")
		}
	}
	email := strings.TrimSpace(getString(m, "email_id"))
	if email == "" || !reEmail.MatchString(email) || len(email) > 100 {
		errs = append(errs, "email_id: required, valid email, max 100 chars")
	}
	mobile := strings.TrimSpace(getString(m, "mobile_no"))
	if mobile == "" || !reMobileET.MatchString(mobile) {
		errs = append(errs, "mobile_no: required, start with 09 or 07 and up to 15 digits")
	}
	if v := strings.TrimSpace(getString(m, "unique_id")); v != "" {
		if !reAlnumOptMax(100).MatchString(v) {
			errs = append(errs, "unique_id: alphanumeric max 100")
		}
	}
	isLogged := strings.TrimSpace(getString(m, "is_logged_in"))
	if !reYN.MatchString(isLogged) {
		errs = append(errs, "is_logged_in: required, Y or N")
	}
	return errs
}

func validateBillSection(m map[string]any) []string {
	errs := []string{}
	if v := strings.TrimSpace(getString(m, "bill_address")); v != "" {
		if !reAlnumExtOptMax(400).MatchString(v) {
			errs = append(errs, "bill_address: invalid chars or too long (max 400)")
		}
	}
	if v := strings.TrimSpace(getString(m, "bill_city")); v != "" {
		if !reAlphaOptMax(50).MatchString(v) {
			errs = append(errs, "bill_city: letters only, max 50")
		}
	}
	if v := strings.TrimSpace(getString(m, "bill_state")); v != "" {
		if !reAlphaOptMax(50).MatchString(v) {
			errs = append(errs, "bill_state: letters only, max 50")
		}
	}
	if v := strings.TrimSpace(getString(m, "bill_country")); v != "" {
		if !reAlphaOptMax(50).MatchString(v) {
			errs = append(errs, "bill_country: letters only, max 50")
		}
	}
	if v := strings.TrimSpace(getString(m, "bill_zip")); v != "" {
		if !regexp.MustCompile(`^[A-Za-z0-9]{0,20}$`).MatchString(v) {
			errs = append(errs, "bill_zip: alphanumeric max 20")
		}
	}
	return errs
}

func validateShipSection(m map[string]any) []string {
	errs := []string{}
	if v := strings.TrimSpace(getString(m, "ship_state")); v != "" {
		if !reAlphaOptMax(50).MatchString(v) {
			errs = append(errs, "ship_state: letters only, max 50")
		}
	}
	if v := strings.TrimSpace(getString(m, "ship_country")); v != "" {
		if !reAlphaOptMax(50).MatchString(v) {
			errs = append(errs, "ship_country: letters only, max 50")
		}
	}
	if v := strings.TrimSpace(getString(m, "ship_zip")); v != "" {
		if !regexp.MustCompile(`^[A-Za-z0-9]{0,20}$`).MatchString(v) {
			errs = append(errs, "ship_zip: alphanumeric max 20")
		}
	}
	if v := strings.TrimSpace(getString(m, "ship_days")); v != "" {
		if !reNumOptMax(11).MatchString(v) {
			errs = append(errs, "ship_days: numeric max 11")
		}
	}
	if v := strings.TrimSpace(getString(m, "address_count")); v != "" {
		if !reNumOptMax(11).MatchString(v) {
			errs = append(errs, "address_count: numeric max 11")
		}
	}
	if v := strings.TrimSpace(getString(m, "ship_address")); v != "" {
		if !reAlnumExtOptMax(400).MatchString(v) {
			errs = append(errs, "ship_address: invalid chars or too long (max 400)")
		}
	}
	if v := strings.TrimSpace(getString(m, "ship_city")); v != "" {
		if !reAlphaOptMax(50).MatchString(v) {
			errs = append(errs, "ship_city: letters only, max 50")
		}
	}
	return errs
}

func validateItemSection(m map[string]any) []string {
	errs := []string{}
	if v := strings.TrimSpace(getString(m, "item_count")); v != "" {
		if !reAlnumOptMax(11).MatchString(v) {
			errs = append(errs, "item_count: alphanumeric max 11")
		}
	}
	if v := strings.TrimSpace(getString(m, "item_value")); v != "" {
		if len(v) > 200 {
			errs = append(errs, "item_value: max 200 chars")
		}
	}
	if v := strings.TrimSpace(getString(m, "item_category")); v != "" {
		if len(v) > 200 {
			errs = append(errs, "item_category: max 200 chars")
		}
	}
	return errs
}

func validateUpiSection(m map[string]any) []string {
	errs := []string{}
	for i := 1; i <= 5; i++ {
		k := fmt.Sprintf("udf_%d", i)
		if v := strings.TrimSpace(getString(m, k)); v != "" {
			if !reAlnumExtOptMax(100).MatchString(v) {
				errs = append(errs, fmt.Sprintf("%s: invalid chars or too long (max 100)", k))
			}
		}
	}
	return errs
}

// --- PreparePayment with full validation collecting ALL errors ---

func (p *PaymentSDK) PreparePayment(b BuildPayload) (*PrepareResult, error) {
	if p.merchantID == "" || p.merchantKeyB64 == "" {
		return nil, errors.New("merchantId and merchantKeyBase64 required")
	}

	// required top-level txn
	if b.Txn == nil {
		return nil, errors.New("txn section required")
	}

	// collect all validation errors
	errs := []string{}

	// validate sections (txn needs p for debug)
	errs = append(errs, p.validateTxnSection(b.Txn)...)
	errs = append(errs, validatePgSection(b.PgDetails)...)
	errs = append(errs, validateCardSection(b.CardDetails)...)
	errs = append(errs, validateCustSection(b.CustDetails)...)
	errs = append(errs, validateBillSection(b.BillDetails)...)
	errs = append(errs, validateShipSection(b.ShipDetails)...)
	errs = append(errs, validateItemSection(b.ItemDetails)...)
	errs = append(errs, validateUpiSection(b.UpiDetails)...)

	// If there are errors, return them all at once
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("validation errors: %s", strings.Join(errs, "; "))
	}

	// All validations passed — prepare encrypt_input and hash_input
	txnKeys := []string{"ag_id", "me_id", "order_no", "amount", "country", "currency", "txn_type", "success_url", "failure_url", "channel"}
	pgKeys := []string{"pg_id", "paymode", "scheme", "wallet_type"}
	cardKeys := []string{"card_no", "exp_month", "exp_year", "cvv", "card_name"}
	custKeys := []string{"cust_name", "email_id", "mobile_no", "unique_id", "is_logged_in"}
	billKeys := []string{"bill_address", "bill_city", "bill_state", "bill_country", "bill_zip"}
	shipKeys := []string{"ship_state", "ship_country", "ship_zip", "ship_days", "address_count", "ship_address", "ship_city"}
	itemKeys := []string{"item_count", "item_value", "item_category"}
	upiKeys := []string{"udf_1", "udf_2", "udf_3", "udf_4", "udf_5"}

	txn_details := buildSection(b.Txn, txnKeys)
	pg_details := buildSection(b.PgDetails, pgKeys)
	card_details := buildSection(b.CardDetails, cardKeys)
	cust_details := buildSection(b.CustDetails, custKeys)
	bill_details := buildSection(b.BillDetails, billKeys)
	ship_details := buildSection(b.ShipDetails, shipKeys)
	item_details := buildSection(b.ItemDetails, itemKeys)
	upi_details := buildSection(b.UpiDetails, upiKeys)
	other_details := strings.TrimSpace(b.Other)

	sections := []string{
		txn_details,
		pg_details,
		card_details,
		cust_details,
		bill_details,
		ship_details,
		item_details,
		other_details,
		upi_details,
	}

	// trim trailing empty sections (so no trailing ~)
	sections = trimTrailingEmptySections(sections)
	encryptInput := strings.Join(sections, "~")

	// hash input
	meID := strings.TrimSpace(getString(b.Txn, "me_id"))
	orderNo := strings.TrimSpace(getString(b.Txn, "order_no"))
	amount := strings.TrimSpace(getString(b.Txn, "amount"))
	country := strings.TrimSpace(getString(b.Txn, "country"))
	currency := strings.TrimSpace(getString(b.Txn, "currency"))
	hashInput := strings.Join([]string{meID, orderNo, amount, country, currency}, "~")

	// merchant_request: encrypt encryptInput with static IV
	merchantRequest, err := encryptCBCBase64([]byte(encryptInput), p.merchantKeyB64, staticIV)
	if err != nil {
		return nil, fmt.Errorf("encrypt merchant_request: %w", err)
	}

	// compute SHA-256 hex and encrypt
	sum := sha256.Sum256([]byte(hashInput))
	shaHex := fmt.Sprintf("%x", sum[:])
	encryptedHash, err := encryptCBCBase64([]byte(shaHex), p.merchantKeyB64, staticIV)
	if err != nil {
		return nil, fmt.Errorf("encrypt hash: %w", err)
	}

	html := buildAutoSubmitHTML(p.gatewayURL, meID, merchantRequest, encryptedHash)

	return &PrepareResult{
		HTML: html,
		//MerchantRequest: merchantRequest,
		//Hash:            encryptedHash,
		//EncryptInput:    encryptInput,
		//HashInput:       hashInput,
		//MerchantID:      meID,
	}, nil
}

func buildAutoSubmitHTML(action, meID, merchantReq, hash string) string {
	escape := func(s string) string {
		replacer := strings.NewReplacer("&", "&amp;", "\"", "&quot;", "<", "&lt;", ">", "&gt;")
		return replacer.Replace(s)
	}
	return fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>Redirecting</title></head>
<body>
  <form id="paymentForm" name="paymentForm" method="POST" enctype="application/x-www-form-urlencoded" action="%s">
    <input type="hidden" name="me_id" value="%s">
    <input type="hidden" name="merchant_request" value="%s">
    <input type="hidden" name="hash" value="%s">
    <noscript><p>JavaScript disabled. Click continue to proceed.</p><button type="submit">Continue</button></noscript>
  </form>
  <script>document.getElementById('paymentForm').submit();</script>
</body></html>`, escape(action), escape(meID), escape(merchantReq), escape(hash))
}

// Optional: expose a simple Validate to allow merchants to pre-check payloads if desired.
func (p *PaymentSDK) Validate(b BuildPayload) []string {
	errs := []string{}
	if b.Txn == nil || strings.TrimSpace(getString(b.Txn, "me_id")) == "" {
		errs = append(errs, "me_id required")
	}
	if b.Txn == nil || strings.TrimSpace(getString(b.Txn, "order_no")) == "" {
		errs = append(errs, "order_no required")
	}
	if b.Txn == nil || strings.TrimSpace(getString(b.Txn, "amount")) == "" {
		errs = append(errs, "amount required")
	}
	sort.Strings(errs)
	return errs
}

// ======================
// Callback decryption helpers
// ======================

// DecryptFieldB64 tries to decrypt a single base64-encoded AES-256-CBC ciphertext.
// It attempts decryption with staticIV first, then zeroIV. Returns plaintext string.
func (p *PaymentSDK) DecryptFieldB64(cipherB64 string) (string, error) {
	if strings.TrimSpace(cipherB64) == "" {
		return "", nil
	}
	// Try static IV first
	plain, err := decryptCBCBase64(cipherB64, p.merchantKeyB64, staticIV)
	if err == nil {
		return string(plain), nil
	}
	// If static IV fails, try zero IV
	plain, err2 := decryptCBCBase64(cipherB64, p.merchantKeyB64, zeroIV)
	if err2 == nil {
		return string(plain), nil
	}
	// return first error if second also fails, but include both info
	return "", fmt.Errorf("decrypt attempts failed: staticErr=%v; zeroErr=%v", err, err2)
}

// DecryptCallbackMap accepts a map[string]string (e.g. parsed form or JSON from PG callback).
// It tries to decrypt commonly encrypted fields and returns a new map with decrypted values
// (if decryption succeeded) and a slice of errors for fields that couldn't be decrypted.
func (p *PaymentSDK) DecryptCallbackMap(in map[string]string) (map[string]string, []error) {
	out := make(map[string]string, len(in))
	errs := []error{}

	// list of fields that are typically AES-CBC+base64 encrypted by PG
	encryptedCandidates := []string{
		"merchant_request",
		"txn_response",
		"pg_details",
		"txn_details",
		"other_details",
		"fraud_details",
		"card_details",
		"cust_details",
		"bill_details",
		"ship_details",
	}

	// copy all keys initially
	for k, v := range in {
		out[k] = v
	}

	// helper to normalize "null" -> ""
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		if strings.EqualFold(s, "null") {
			return ""
		}
		return s
	}

	for _, k := range encryptedCandidates {
		if v, ok := in[k]; ok && strings.TrimSpace(v) != "" {
			dec, err := p.DecryptFieldB64(v)
			if err != nil {
				// keep original value but record error
				errs = append(errs, fmt.Errorf("%s: %w", k, err))
				if p.Debug {
					log.Printf("DecryptCallbackMap: failed to decrypt %s: %v\n", k, err)
				}
				continue
			}

			// put decrypted value into output
			out[k] = dec

			// If this is txn_response, try to parse subfields and set them in output
			if k == "txn_response" {
				// expected format (pipe-separated):
				// ag_id|me_id|orderNo|amount|country|currency|date|time|transactionId|agNumber|status|static_qr_id|payment_link_receipt|finalAmount
				tokens := strings.Split(dec, "|")

				get := func(i int) string {
					if i < 0 || i >= len(tokens) {
						return ""
					}
					return norm(tokens[i])
				}

				// map tokens into named fields (use same key names your handlers/frontend expect)
				if v := get(0); v != "" {
					out["ag_id"] = v
				}
				if v := get(1); v != "" {
					out["me_id"] = v
				}
				if v := get(2); v != "" {
					out["orderNo"] = v
				}
				if v := get(3); v != "" {
					out["amount"] = v
				}
				// country and currency are sometimes swapped in other systems; follow example mapping:
				if v := get(4); v != "" {
					out["country"] = v
				}
				if v := get(5); v != "" {
					out["currency"] = v
				}
				datePart := get(6)
				timePart := get(7)
				if datePart != "" && timePart != "" {
					out["dateAndTime"] = datePart + " " + timePart
				} else if datePart != "" {
					out["dateAndTime"] = datePart
				}
				if v := get(8); v != "" {
					out["transactionId"] = v
				}
				if v := get(9); v != "" {
					out["agNumber"] = v
				}
				if v := get(10); v != "" {
					out["status"] = v
				}
				if v := get(11); v != "" {
					out["static_qr_id"] = v
				}
				if v := get(12); v != "" {
					out["payment_link_receipt"] = v
				}
				if v := get(13); v != "" {
					out["finalAmount"] = v
				}

				if p.Debug {
					log.Printf("Parsed txn_response tokens for orderNo=%s transactionId=%s status=%s\n",
						out["orderNo"], out["transactionId"], out["status"])
				}
			}
		}
	}
	return out, errs
}

// Alternative helper if callback comes as url.Values (e.g. from an HTTP form POST)
func (p *PaymentSDK) DecryptCallbackValues(vals url.Values) (map[string]string, []error) {
	in := make(map[string]string)
	for k := range vals {
		in[k] = vals.Get(k)
	}
	return p.DecryptCallbackMap(in)
}
