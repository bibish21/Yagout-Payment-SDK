<<<<<<< HEAD
# Go Backend

## Run
```bash
cd backend
go mod tidy
cp .env.example .env
# edit .env if needed
go run ./cmd/server
```
Server listens on `PORT` (default 5003).

### Endpoint
POST `/api/create-payment` — body:
```json
{
  "txn": { "ag_id":"yagout","me_id":"202508080001","order_no":"ORD123","amount":"10.00","country":"ETH","currency":"ETB","txn_type":"SALE","success_url":"https://example/s","failure_url":"https://example/f","channel":"WEB" },
  "cust_details": { "email_id":"a@b.com","mobile_no":"900000000","is_logged_in":"Y" }
}
```
Returns:
```json
{
  "html": "<!doctype...>",
  "merchant_request": "base64...",
  "hash": "base64...",
  "encrypt_input": "section~section~...",
  "hash_input": "me_id~order_no~amount~country~currency",
  "merchantId": "202508080001"
}
```
=======


# Yagoutpay Nodejs payment-sdk

A lightweight and secure **Payment SDK** for preparing and validating payment requests between a merchant frontend, backend, and payment gateway.
It ensures **data type validation**, **length validation**, **correct parameter ordering**, **encryption & hashing** for secure merchant transactions, and **prepare html request**.

---

## 📦 Features

* ✅ Validates request payload (type & length) before processing.
* 🔒 Encrypts sensitive merchant request data.
* 🧾 Generates secure hash for request verification.
* 📄 Supports Ethiopian phone number validation (09, 07).
* 🔄 Works seamlessly between **backend and payment gateway**.
* 🛠 Easily integrable into **GOLANG** backends.

---

## 🏗 Architecture

```
Frontend  →  Backend  →  payment-sdk  → backend -> Frontend -> Payment Gateway
```

**Flow:**

1. **Frontend** sends payment request to backend.
2. **Backend** calls `payment-sdk` with payload.
3. **payment-sdk**:

   * Validates field types & lengths.
   * Orders parameters according to the gateway specification.
   * Builds encryption & hash strings.
   * prepare HTML form
4. Backend returns the **prepared HTML form** or **API payload** to the frontend.
5. Frontend redirects user to the payment gateway.

---

## 📥 Installation

```bash
npm install payment-sdk
```

---

## ⚙️ Usage

### **Backend Example**

```go
//import the sdk
import (
    "fmt"
    "log"
    "github.com/yourorg/payment-sdk-go/sdk" // import your SDK
)
//call PreparePayment and pass the payload you prepared.
func PaymentHandler(w http.ResponseWriter, r *http.Request) {
    res, err := s.sdk.PreparePayment(payload)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "text/html")
    w.Write([]byte(res.HTML))
}
```

---

## 🧪 Ethiopian Phone Validation

The SDK validates Ethiopian phone numbers to start with:

* `09`
* `07`

Example Regex:

```ts
const phoneRegex = /^0[97]\d{8}$/;
```

---

## 📜 API Reference



### **`preparePayment(data: object): object`** //this is inside the SDK

* Validates Field types.
* Validates Field lengths.
* Orders parameters based on gateway specification.
* Builds encrypted string.
* Generates secure hash.
* Generates HTML request data.

**Returns**:

```ts
{
  html: string,        // Ready-to-submit payment form (if needed)
  merchant request (encrypted): string,   // Encrypted merchant data
  hash: string         // Secure hash for verification
}
```

---

## 🛡 Security

* Uses **AES-256-CBC** for encryption.
* Uses **SHA-256** for hashing.

---


>>>>>>> 3a3704133c64c5a762df15febd2ea68445612700
