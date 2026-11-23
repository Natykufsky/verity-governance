package tests

import (
	"bytes"
	"strings"
	"testing"

	gov "github.com/Natykufsky/verity-governance"
)

func TestCrypto_CanonicalizationDeterminism(t *testing.T) {
	c, err := gov.NewLocalCryptoProvider("test-master-secret")
	if err != nil {
		t.Fatalf("NewLocalCryptoProvider: %v", err)
	}

	p1 := map[string]any{
		"zebra":  1,
		"alpha":  "hello <world> & friends",
		"nested": map[string]any{"b": true, "a": []any{3, 2, 1}},
	}
	p2 := map[string]any{
		"nested": map[string]any{"a": []any{3, 2, 1}, "b": true},
		"alpha":  "hello <world> & friends",
		"zebra":  1,
	}

	b1, err := c.Canonicalize(p1)
	if err != nil {
		t.Fatalf("canonicalize p1: %v", err)
	}
	b2, err := c.Canonicalize(p2)
	if err != nil {
		t.Fatalf("canonicalize p2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("canonical bytes differ:\n%s\nvs\n%s", b1, b2)
	}
	if !bytes.Equal(c.Hash(b1), c.Hash(b2)) {
		t.Fatalf("hashes differ for identical logical payloads")
	}
	if strings.Contains(string(b1), `\u003c`) {
		t.Fatalf("canonical JSON should not HTML-escape '<': %s", b1)
	}
}

func TestCrypto_EnvelopeEncV2_TamperAndKeyRotation(t *testing.T) {
	c, err := gov.NewLocalCryptoProvider("secret-v1")
	if err != nil {
		t.Fatalf("NewLocalCryptoProvider: %v", err)
	}

	plain := []byte(`{"account_no":"0123456789","amount":50000}`)
	encV1, err := c.Encrypt("org-123", plain)
	if err != nil {
		t.Fatalf("encrypt v1: %v", err)
	}
	if !strings.HasPrefix(string(encV1), "enc:v2:org-123:1:") {
		t.Fatalf("unexpected envelope prefix: %s", encV1)
	}
	if bytes.Contains(encV1, []byte("0123456789")) {
		t.Fatalf("ciphertext must not contain plaintext")
	}

	// Rotate to key version 2; version 1 ciphertext must still decrypt
	c.RegisterKey("2", "secret-v2", true)
	decV1, err := c.Decrypt(encV1)
	if err != nil || !bytes.Equal(decV1, plain) {
		t.Fatalf("decrypt v1 after rotation failed: err=%v dec=%s", err, decV1)
	}

	encV2, err := c.Encrypt("org-123", plain)
	if err != nil {
		t.Fatalf("encrypt v2: %v", err)
	}
	if !strings.HasPrefix(string(encV2), "enc:v2:org-123:2:") {
		t.Fatalf("expected v2 active prefix, got: %s", encV2)
	}

	// Tamper with AAD header workspace -> must fail authentication
	tamperedHeader := bytes.Replace(encV2, []byte("org-123"), []byte("org-999"), 1)
	if _, err := c.Decrypt(tamperedHeader); err == nil {
		t.Fatalf("expected decrypt failure on tampered AAD header")
	}

	// Tamper with ciphertext byte -> must fail authentication
	tamperedBody := append([]byte(nil), encV2...)
	tamperedBody[len(tamperedBody)-3] ^= 0x01
	if _, err := c.Decrypt(tamperedBody); err == nil {
		t.Fatalf("expected decrypt failure on flipped ciphertext byte")
	}
}

func TestCrypto_SignAndVerify(t *testing.T) {
	c, _ := gov.NewLocalCryptoProvider("sig-secret")
	hash := c.Hash([]byte(`{"amount":100}`))
	sig, err := c.Sign("org|finance.disburse|scope|stipend|1", hash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !c.Verify("org|finance.disburse|scope|stipend|1", hash, sig) {
		t.Fatalf("expected valid signature")
	}
	if c.Verify("org|finance.disburse|other-scope|stipend|1", hash, sig) {
		t.Fatalf("expected signature verification failure on modified meta")
	}
}

