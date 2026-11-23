package governance

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// LocalCryptoProvider implements CryptoProvider using:
//   - RFC 8785-style deterministic JSON canonicalization
//   - SHA-256 content hashing
//   - Ed25519 signing/verification over request metadata + payload hash
//   - AES-256-GCM envelope encryption formatted as `enc:v2:<workspace>:<dek_version>:<base64>`
type LocalCryptoProvider struct {
	activeVersion string
	keys          map[string][]byte // version -> 32-byte AES-256 DEK
	signingKey    ed25519.PrivateKey
	verifyKey     ed25519.PublicKey
}

// NewLocalCryptoProvider constructs a LocalCryptoProvider from a master secret (and optional 32-byte Ed25519 seed).
// Additional rotated decryption keys can be registered via RegisterLegacyKey.
func NewLocalCryptoProvider(masterSecret string, signingSeed ...[]byte) (*LocalCryptoProvider, error) {
	if strings.TrimSpace(masterSecret) == "" {
		return nil, errors.New("governance crypto: master secret must not be empty")
	}
	dek := sha256.Sum256([]byte("verity-governance:dek:v1:" + masterSecret))

	var priv ed25519.PrivateKey
	if len(signingSeed) > 0 && len(signingSeed[0]) == ed25519.SeedSize {
		priv = ed25519.NewKeyFromSeed(signingSeed[0])
	} else {
		derived := sha256.Sum256([]byte("verity-governance:ed25519:v1:" + masterSecret))
		priv = ed25519.NewKeyFromSeed(derived[:ed25519.SeedSize])
	}
	pub := priv.Public().(ed25519.PublicKey)

	return &LocalCryptoProvider{
		activeVersion: "1",
		keys: map[string][]byte{
			"1": dek[:],
		},
		signingKey: priv,
		verifyKey:  pub,
	}, nil
}

// RegisterKey registers an encryption key version; if makeActive is true, new encryptions use it.
func (c *LocalCryptoProvider) RegisterKey(version string, secret string, makeActive bool) {
	dek := sha256.Sum256([]byte("verity-governance:dek:v" + version + ":" + secret))
	c.keys[version] = dek[:]
	if makeActive {
		c.activeVersion = version
	}
}

// PublicKey returns the Ed25519 public key used to verify payload signatures.
func (c *LocalCryptoProvider) PublicKey() ed25519.PublicKey {
	return c.verifyKey
}

// Canonicalize produces deterministic, key-sorted, compact JSON bytes (RFC 8785 JCS compatible).
func (c *LocalCryptoProvider) Canonicalize(payload map[string]any) ([]byte, error) {
	if payload == nil {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, payload); err != nil {
		return nil, fmt.Errorf("governance crypto: canonicalize: %w", err)
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := marshalNoEscape(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		b, err := marshalNoEscape(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Hash computes SHA-256 over canonical payload bytes.
func (c *LocalCryptoProvider) Hash(canonical []byte) []byte {
	sum := sha256.Sum256(canonical)
	return sum[:]
}

// Sign computes an Ed25519 signature over request metadata + payload hash.
func (c *LocalCryptoProvider) Sign(meta string, hash []byte) ([]byte, error) {
	msg := buildSigningMessage(meta, hash)
	return ed25519.Sign(c.signingKey, msg), nil
}

// Verify checks the Ed25519 signature over request metadata + payload hash.
func (c *LocalCryptoProvider) Verify(meta string, hash, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := buildSigningMessage(meta, hash)
	return ed25519.Verify(c.verifyKey, msg, sig)
}

func buildSigningMessage(meta string, hash []byte) []byte {
	msg := make([]byte, 0, len(meta)+1+len(hash))
	msg = append(msg, []byte(meta)...)
	msg = append(msg, '|')
	msg = append(msg, hash...)
	return msg
}

// Encrypt seals plaintext using AES-256-GCM and encodes as `enc:v2:<workspace>:<dek_version>:<base64>`.
// The envelope prefix (`enc:v2:<workspace>:<dek_version>`) is bound as GCM Additional Authenticated Data (AAD)
// so tampering with the workspace or key version header fails decryption.
func (c *LocalCryptoProvider) Encrypt(workspace string, plaintext []byte) ([]byte, error) {
	if workspace == "" {
		workspace = "default"
	}
	key, ok := c.keys[c.activeVersion]
	if !ok {
		return nil, fmt.Errorf("governance crypto: active key version %q not found", c.activeVersion)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aad := fmt.Sprintf("enc:v2:%s:%s", workspace, c.activeVersion)
	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(aad))
	encoded := fmt.Sprintf("%s:%s", aad, base64.StdEncoding.EncodeToString(sealed))
	return []byte(encoded), nil
}

// Decrypt validates the `enc:v2:` envelope header and decrypts AES-256-GCM ciphertext.
func (c *LocalCryptoProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	parts := strings.SplitN(string(ciphertext), ":", 5)
	if len(parts) != 5 || parts[0] != "enc" || parts[1] != "v2" {
		return nil, errors.New("governance crypto: invalid enc:v2 envelope format")
	}
	workspace, version, b64 := parts[2], parts[3], parts[4]
	key, ok := c.keys[version]
	if !ok {
		return nil, fmt.Errorf("governance crypto: unknown key version %q", version)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("governance crypto: base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("governance crypto: ciphertext truncated")
	}
	aad := fmt.Sprintf("enc:v2:%s:%s", workspace, version)
	plain, err := gcm.Open(nil, raw[:ns], raw[ns:], []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("governance crypto: decrypt/authenticate failed: %w", err)
	}
	return plain, nil
}

