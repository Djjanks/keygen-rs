// Generates the ArtifactVerifier test vectors in src/artifact.rs with the code `keygen upload`
// uses. calculateChecksum and calculateSignature below are copied verbatim from keygen-cli:
// https://github.com/keygen-sh/keygen-cli/blob/3fa3a562d237ee0415b38576fa5b8bd38c94a629/cmd/upload.go#L359-L453
// The glue above them stands in for keygen-cli's flags with their defaults
// (cmd/upload.go#L87-L93) and for keygenext.Product (the Ed25519ph context).
//
//	go run .
package main

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

var uploadOpts = struct {
	ChecksumAlgorithm string
	ChecksumEncoding  string
	SigningAlgorithm  string
	SignatureEncoding string
}{
	ChecksumAlgorithm: "sha-512",
	ChecksumEncoding:  "base64raw",
	SigningAlgorithm:  "ed25519ph",
	SignatureEncoding: "base64raw",
}

var keygenext = struct{ Product string }{Product: "test-product-id"}

func yellow(a ...interface{}) string { return fmt.Sprint(a...) }

func main() {
	payload := "hello keygen"

	file, err := os.CreateTemp("", "artifact-test-vectors")
	if err != nil {
		panic(err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.WriteString(payload); err != nil {
		panic(err)
	}
	file.Seek(0, io.SeekStart)

	// Same key format as `keygen genkey` (cmd/genkey.go): hex of the 64-byte private key
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1) // 0x01..=0x20
	}
	signingKey := ed25519.NewKeyFromSeed(seed)
	publicKey := signingKey.Public().(ed25519.PublicKey)

	checksum, err := calculateChecksum(file)
	if err != nil {
		panic(err)
	}
	signature, err := calculateSignature(hex.EncodeToString(signingKey), file)
	if err != nil {
		panic(err)
	}

	uploadOpts.ChecksumAlgorithm = "sha-256"
	checksum256, err := calculateChecksum(file)
	if err != nil {
		panic(err)
	}

	fmt.Printf("const PAYLOAD: &[u8] = b%q;\n", payload)
	fmt.Printf("const CONTEXT: &str = %q;\n", keygenext.Product)
	fmt.Printf("const PUBLIC_KEY: &str = %q;\n", hex.EncodeToString(publicKey))
	fmt.Printf("const CHECKSUM: &str = %q;\n", checksum)
	fmt.Printf("const SIGNATURE: &str = %q;\n", signature)
	fmt.Printf("// --checksum-algorithm sha-256: %q\n", checksum256)
	fmt.Printf("// keygen.key: %s\n", hex.EncodeToString(signingKey))
}

func calculateChecksum(file *os.File) (string, error) {
	defer file.Seek(0, io.SeekStart) // reset reader
	var h hash.Hash

	switch uploadOpts.ChecksumAlgorithm {
	case "sha-512":
		h = sha512.New()
	case "sha-256":
		h = sha256.New()
	case "sha-1":
		h = sha1.New()
	default:
		return "", fmt.Errorf(`checksum algorithm "%s" is not supported`, uploadOpts.ChecksumAlgorithm)
	}

	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}

	digest := h.Sum(nil)

	switch uploadOpts.ChecksumEncoding {
	case "base64":
		return base64.StdEncoding.EncodeToString(digest), nil
	case "base64raw":
		return base64.RawStdEncoding.EncodeToString(digest), nil
	case "base64url":
		return base64.URLEncoding.EncodeToString(digest), nil
	case "hex":
		return hex.EncodeToString(digest), nil
	default:
		return "", fmt.Errorf(`checksum encoding "%s" is not supported`, uploadOpts.ChecksumEncoding)
	}
}

func calculateSignature(encSigningKey string, file *os.File) (string, error) {
	defer file.Seek(0, io.SeekStart) // reset reader

	decSigningKey, err := hex.DecodeString(encSigningKey)
	if err != nil {
		return "", fmt.Errorf("bad signing key (%s)", err)
	}

	if l := len(decSigningKey); l != ed25519.PrivateKeySize {
		return "", fmt.Errorf("bad signing key length (got %d expected %d)", l, ed25519.PrivateKeySize)
	}

	signingKey := ed25519.PrivateKey(decSigningKey)
	var sig []byte

	switch uploadOpts.SigningAlgorithm {
	case "ed25519ph":
		// We're using Ed25519ph which expects a pre-hashed message using SHA-512
		h := sha512.New()

		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}

		opts := &ed25519.Options{Hash: crypto.SHA512, Context: keygenext.Product}
		digest := h.Sum(nil)

		sig, err = signingKey.Sign(nil, digest, opts)
		if err != nil {
			return "", err
		}
	case "ed25519":
		fmt.Println(yellow("warning:") + " using ed25519 to sign large files is not recommended (use ed25519ph instead)")

		b, err := ioutil.ReadAll(file)
		if err != nil {
			return "", err
		}

		sig, err = signingKey.Sign(nil, b, &ed25519.Options{})
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf(`signing algorithm "%s" is not supported`, uploadOpts.SigningAlgorithm)
	}

	switch uploadOpts.SignatureEncoding {
	case "base64":
		return base64.StdEncoding.EncodeToString(sig), nil
	case "base64raw":
		return base64.RawStdEncoding.EncodeToString(sig), nil
	case "base64url":
		return base64.URLEncoding.EncodeToString(sig), nil
	case "hex":
		return hex.EncodeToString(sig), nil
	default:
		return "", fmt.Errorf(`signature encoding "%s" is not supported`, uploadOpts.SignatureEncoding)
	}
}
