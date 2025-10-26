package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTempDB(t *testing.T) *sql.DB {
	t.Helper()
	tmp := t.TempDir()
	path := tmp + "/test.db"
	t.Setenv("DB_PATH", path)
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB error: %v", err)
	}
	if err := seedIfNeeded(db); err != nil {
		t.Fatalf("seedIfNeeded error: %v", err)
	}
	return db
}

func TestRSAPEMRoundtripAndInvalid(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	p := rsaToPEM(k)
	got, _ := pemToRSA(p)
	if got.PublicKey.N.Cmp(k.PublicKey.N) != 0 || got.PublicKey.E != k.PublicKey.E {
		t.Fatalf("roundtrip mismatch")
	}
	if _, err := pemToRSA([]byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----")); err == nil {
		t.Fatalf("expected error for invalid pem")
	}
	if _, err := pemToRSA([]byte("not pem data")); err == nil {
		t.Fatalf("expected error for non-pem")
	}
}

func TestDBAndKeySelection(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	ka, _ := pickKey(db, false)
	if ka.Exp <= time.Now().Unix() {
		t.Fatalf("expected active key exp in future")
	}
	ke, _ := pickKey(db, true)
	if ke.Exp > time.Now().Unix() {
		t.Fatalf("expected expired key exp in past")
	}
	acts, _ := listActive(db)
	if len(acts) == 0 {
		t.Fatalf("expected at least 1 active key")
	}
	for _, r := range acts {
		if r.Exp <= time.Now().Unix() {
			t.Fatalf("active list contains expired exp=%d", r.Exp)
		}
	}
}

func TestNoKeysError(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DB_PATH", tmp+"/empty.db")
	db, _ := openDB()
	defer db.Close()
	// Don't seed - should get error
	_, err := pickKey(db, false)
	if err == nil {
		t.Fatalf("expected error when no keys")
	}
}

func TestSeedIdempotency(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	// Second seed should not add more keys
	var cnt1 int
	db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&cnt1)
	seedIfNeeded(db)
	var cnt2 int
	db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&cnt2)
	if cnt1 != cnt2 {
		t.Fatalf("seed not idempotent: %d vs %d", cnt1, cnt2)
	}
}

func TestJWKSHandlers(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	mux := buildMux(db)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("jwks GET status=%d", w.Code)
	}
	var jwks JWKS
	json.Unmarshal(w.Body.Bytes(), &jwks)
	if len(jwks.Keys) == 0 {
		t.Fatalf("expected keys in jwks")
	}
	for _, k := range jwks.Keys {
		if _, err := strconv.ParseInt(k.Kid, 10, 64); err != nil {
			t.Fatalf("kid not numeric: %q", k.Kid)
		}
	}
	// HEAD JWKS
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/jwks", nil))
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD failed")
	}
	// Method not allowed
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/jwks", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405")
	}
}

func TestJWKSWithBadKey(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	// Insert bad PEM
	db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, []byte("bad"), time.Now().Add(time.Hour).Unix())
	mux := buildMux(db)
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	// Should still work, just skip bad key
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 despite bad key")
	}
}

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	parts := strings.Split(token, ".")
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func verifyRS256Signature(t *testing.T, token string, pub *rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	h := sha256.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h.Sum(nil), sig)
}

func TestAuthEndpointActiveAndExpired(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	mux := buildMux(db)
	activeRow, _ := pickKey(db, false)
	privA, _ := pemToRSA(activeRow.Pem)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth", nil))
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["token"] == "" || verifyRS256Signature(t, resp["token"], &privA.PublicKey) != nil {
		t.Fatalf("active token invalid")
	}
	if int64(decodeJWTPayload(t, resp["token"])["exp"].(float64)) <= time.Now().Unix() {
		t.Fatalf("active token exp should be future")
	}
	// Expired token
	expRow, _ := pickKey(db, true)
	privE, _ := pemToRSA(expRow.Pem)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth?expired", nil))
	json.Unmarshal(w.Body.Bytes(), &resp)
	if verifyRS256Signature(t, resp["token"], &privE.PublicKey) != nil {
		t.Fatalf("expired token sig invalid")
	}
	if int64(decodeJWTPayload(t, resp["token"])["exp"].(float64)) >= time.Now().Unix() {
		t.Fatalf("expired token exp should be past")
	}
}

func TestAuthMethodNotAllowed(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	mux := buildMux(db)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405")
	}
}

func TestAuthWithBadKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DB_PATH", tmp+"/bad.db")
	db, _ := openDB()
	defer db.Close()
	db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, []byte("corrupt"), time.Now().Add(time.Hour).Unix())
	mux := buildMux(db)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for bad key")
	}
}

func TestB64URLAndJWKHelpers(t *testing.T) {
	if b64url([]byte{0x01, 0x00, 0x01}) != "AQAB" {
		t.Fatalf("b64url unexpected")
	}
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	jw := pubToJWK(&k.PublicKey, "kid-1")
	if jw.Kty != "RSA" || jw.Alg != "RS256" || jw.Use != "sig" || jw.Kid != "kid-1" || jw.E != "AQAB" {
		t.Fatalf("jwk fields mismatch")
	}
}

func TestLogRequestsWrapper(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	srv := httptest.NewServer(logRequests(h))
	defer srv.Close()
	resp, _ := http.Get(srv.URL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

func TestRunGracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	if err := run(ctx, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})); err != nil {
		t.Fatalf("run error: %v", err)
	}
}

func TestShortKIDFromPub(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	s := shortKIDFromPub(&k.PublicKey)
	if len(s) != 16 || !strings.ContainsRune("0123456789abcdef", rune(s[0])) {
		t.Fatalf("short kid invalid: %s", s)
	}
}

func TestOpenDBWithDefaultPath(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(tmp)
	t.Setenv("DB_PATH", "")
	db, _ := openDB()
	defer db.Close()
	var cnt int
	db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&cnt)
}

func TestRootEndpoint(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	mux := buildMux(db)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Body.String() != "ok" {
		t.Fatalf("root failed")
	}
}

func TestDBPathWhitespace(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(tmp)
	t.Setenv("DB_PATH", "   ")
	db, _ := openDB()
	defer db.Close()
	if _, err := os.Stat(dbFileDefault); err != nil {
		t.Fatalf("default db not created")
	}
}

func TestListActiveWithRows(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	// Insert multiple active keys
	for i := 0; i < 3; i++ {
		k, _ := rsa.GenerateKey(rand.Reader, 1024)
		pem := rsaToPEM(k)
		db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, pem, time.Now().Add(time.Hour).Unix())
	}
	keys, _ := listActive(db)
	if len(keys) < 3 {
		t.Fatalf("expected at least 3 active keys, got %d", len(keys))
	}
}

func TestJWKSDBError(t *testing.T) {
	db := newTempDB(t)
	mux := buildMux(db)
	_ = db.Close() // force DB error inside handler

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when db closed, got %d", w.Code)
	}
}

func TestAuthEndpointNoKeys503(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DB_PATH", tmp+"/empty.db")
	db, err := openDB()
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.Close()
	// no seeding -> no keys
	mux := buildMux(db)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no keys, got %d", w.Code)
	}
}

func TestRunBadAddrReturnsError(t *testing.T) {
	ctx := context.Background()
	err := run(ctx, "bad-addr", http.NewServeMux())
	if err == nil {
		t.Fatalf("expected error for bad addr")
	}
}

func TestJWKSKeyMatchesPEM(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()

	row, err := pickKey(db, false)
	if err != nil {
		t.Fatalf("pickKey: %v", err)
	}
	priv, err := pemToRSA(row.Pem)
	if err != nil {
		t.Fatalf("pem parse: %v", err)
	}

	mux := buildMux(db)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("jwks status: %d", w.Code)
	}
	var jwks JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("jwks json: %v", err)
	}

	targetKid := strconv.FormatInt(row.Kid, 10)
	var found *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == targetKid {
			found = &jwks.Keys[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("kid %s not found in jwks", targetKid)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(found.N)
	if err != nil {
		t.Fatalf("decode N: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(found.E)
	if err != nil {
		t.Fatalf("decode E: %v", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	if n.Cmp(priv.PublicKey.N) != 0 || e != priv.PublicKey.E {
		t.Fatalf("jwks key does not match pem public key")
	}
}

func TestJWTHeaderKidPresent(t *testing.T) {
	db := newTempDB(t)
	defer db.Close()
	mux := buildMux(db)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("auth status: %d", w.Code)
	}

	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	tok := resp["token"]
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid jwt")
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var hdr, payload map[string]any
	_ = json.Unmarshal(hb, &hdr)
	_ = json.Unmarshal(pb, &payload)

	if hdr["kid"] == nil || hdr["kid"] != payload["kid"] {
		t.Fatalf("missing or mismatched kid in header/payload")
	}
	if hdr["alg"] != "RS256" {
		t.Fatalf("unexpected alg: %v", hdr["alg"])
	}
}
