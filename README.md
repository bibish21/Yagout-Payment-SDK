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