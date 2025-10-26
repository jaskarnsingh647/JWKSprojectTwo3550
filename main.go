// Jaskarn Singh, js2411
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

const dbFileDefault = "totally_not_my_privateKeys.db"

type dbKey struct {
	Kid int64
	Pem []byte
	Exp int64 // unix seconds
}

func openDB() (*sql.DB, error) {
	path := os.Getenv("DB_PATH")
	if strings.TrimSpace(path) == "" {
		path = dbFileDefault
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// Gentle concurrency behavior
	if _, err := db.Exec(`PRAGMA busy_timeout = 2000;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Table schema
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		_ = db.Close()
	}
	return db, err
}

// RSA key serialize/deserialize (PKCS1 PEM)

func rsaToPEM(priv *rsa.PrivateKey) []byte {
	b := x509.MarshalPKCS1PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: b})
}
func pemToRSA(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid PEM format or type: expected 'RSA PRIVATE KEY'")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Seeding: to ensure one expired and one active key exist

func seedIfNeeded(db *sql.DB) error {
	now := time.Now().Unix()
	var activeCnt, expiredCnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM keys WHERE exp > ?`, now).Scan(&activeCnt); err != nil {
		return err
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM keys WHERE exp <= ?`, now).Scan(&expiredCnt); err != nil {
		return err
	}
	// Insert helper (parameterized).
	insert := func(exp int64) error {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Printf("key generation error: %v", err)
			return err
		}
		pem := rsaToPEM(k)
		_, err = db.Exec(`INSERT INTO keys(key, exp) VALUES(?, ?)`, pem, exp)
		return err
	}
	if activeCnt == 0 {
		if err := insert(time.Now().Add(1 * time.Hour).Unix()); err != nil {
			return err
		}
	}
	if expiredCnt == 0 {
		if err := insert(time.Now().Add(-1 * time.Hour).Unix()); err != nil {
			return err
		}
	}
	return nil
}

// DB reads (all parameterized)

func pickKey(db *sql.DB, wantExpired bool) (*dbKey, error) {
	now := time.Now().Unix()
	var row *sql.Row
	if wantExpired {
		row = db.QueryRow(`SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1`, now)
	} else {
		row = db.QueryRow(`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1`, now)
	}
	var k dbKey
	if err := row.Scan(&k.Kid, &k.Pem, &k.Exp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("no keys found matching the criteria")
		}
		return nil, err
	}
	return &k, nil
}

func listActive(db *sql.DB) ([]dbKey, error) {
	now := time.Now().Unix()
	rows, err := db.Query(`SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dbKey
	for rows.Next() {
		var k dbKey
		if err := rows.Scan(&k.Kid, &k.Pem, &k.Exp); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// JWK/JWKS helpers

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func pubToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: b64url(pub.N.Bytes()),
		E: b64url(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// HTTP

func buildMux(db *sql.DB) http.Handler {
	mux := http.NewServeMux()

	// JWKS (GET/HEAD). Only non-expired keys.
	serveJWKS := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			keys, err := listActive(db)
			if err != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			jwks := JWKS{Keys: make([]JWK, 0, len(keys))}
			for _, row := range keys {
				priv, err := pemToRSA(row.Pem)
				if err != nil {
					continue // skips bad rows
				}
				jwks.Keys = append(jwks.Keys, pubToJWK(&priv.PublicKey, strconv.FormatInt(row.Kid, 10)))
			}
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
	mux.HandleFunc("/.well-known/jwks.json", serveJWKS)
	mux.HandleFunc("/jwks", serveJWKS) // bonus mirror

	// /auth issues a JWT. If ?expired present -> use expired key & expired exp.
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Accept Basic or JSON body; ignore content (mock auth).
		// Pick key from DB:
		useExpired := r.URL.Query().Has("expired")
		row, err := pickKey(db, useExpired)
		if err != nil {
			http.Error(w, "no suitable key", http.StatusServiceUnavailable)
			return
		}
		priv, err := pemToRSA(row.Pem)
		if err != nil {
			http.Error(w, "bad key", http.StatusInternalServerError)
			return
		}
		now := time.Now()
		expTime := time.Unix(row.Exp, 0)
		if useExpired {
			expTime = now.Add(-1 * time.Hour) // Ensure expired token
		}
		claims := jwt.MapClaims{
			"sub": "userABC",                   // mock user
			"iss": "go-jwks-sqlite",            // issuer
			"iat": jwt.NewNumericDate(now),     // issued at
			"exp": jwt.NewNumericDate(expTime), // exp from DB
			"kid": strconv.FormatInt(row.Kid, 10),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = claims["kid"]
		signed, err := tok.SignedString(priv)
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": signed})
	})

	// Small root to prove liveness
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return mux
}

// logRequests: simple access log
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// run(server) so tests can exercise startup/shutdown
func run(ctx context.Context, addr string, h http.Handler) error {
	s := &http.Server{Addr: addr, Handler: logRequests(h)}
	go func() {
		<-ctx.Done()
		log.Println("server is shutting down...")
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.Shutdown(c); err != nil {
			log.Printf("server shutdown error: %v", err)
		} else {
			log.Println("server gracefully stopped")
		}
	}()
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func main() {
	db, err := openDB()
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer db.Close()
	if err := seedIfNeeded(db); err != nil {
		log.Fatalf("seed: %v", err)
	}
	mux := buildMux(db)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("JWKS server listening on :8080 (DB=%s)", dbFileDefault)
	if err := run(ctx, ":8080", mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// helper: short readable kid hash
func shortKIDFromPub(pub *rsa.PublicKey) string {
	sum := sha1.Sum(pub.N.Bytes())
	return hex.EncodeToString(sum[:8])
}
