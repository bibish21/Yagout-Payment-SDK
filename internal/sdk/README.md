

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

