package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testCredentialPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "credential test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestReadRejectsNonCanonicalAndNonRegularPaths(t *testing.T) {
	if _, err := Read("relative.crt", PublicCertificate); err == nil {
		t.Fatal("relative credential path accepted")
	}
	if _, err := Read(t.TempDir(), PublicCertificate); err == nil {
		t.Fatal("directory accepted as credential leaf")
	}
}

func TestReadRejectsLeafAndParentSymlinks(t *testing.T) {
	base := t.TempDir()
	realDirectory := filepath.Join(base, "real")
	if err := os.Mkdir(realDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDirectory, "credential.crt")
	if err := os.WriteFile(realFile, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	leafLink := filepath.Join(base, "leaf-link.crt")
	if err := os.Symlink(realFile, leafLink); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := Read(leafLink, PublicCertificate); err == nil {
		t.Fatal("symbolic-link credential leaf accepted")
	}
	parentLink := filepath.Join(base, "parent-link")
	if err := os.Symlink(realDirectory, parentLink); err != nil {
		t.Skipf("directory symbolic links unavailable: %v", err)
	}
	if _, err := Read(filepath.Join(parentLink, "credential.crt"), PublicCertificate); err == nil {
		t.Fatal("symbolic-link credential parent accepted")
	}
}

func TestLeafCertificatePEMRequiresExactlyOneUnadornedCertificate(t *testing.T) {
	certificatePEM, keyPEM := testCredentialPEM(t)
	if err := validateLeafCertificatePEM(append([]byte(" \r\n"), append(certificatePEM, '\t')...)); err != nil {
		t.Fatalf("valid leaf certificate rejected: %v", err)
	}
	rejected := map[string][]byte{
		"empty":               nil,
		"two certificates":    append(append([]byte(nil), certificatePEM...), certificatePEM...),
		"private key":         keyPEM,
		"certificate and key": append(append([]byte(nil), certificatePEM...), keyPEM...),
		"leading garbage":     append([]byte("garbage\n"), certificatePEM...),
		"trailing garbage":    append(append([]byte(nil), certificatePEM...), []byte("garbage")...),
		"invalid DER":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
		"PEM headers": pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Headers: map[string]string{"Comment": "not permitted"}, Bytes: []byte("invalid"),
		}),
	}
	for name, contents := range rejected {
		t.Run(name, func(t *testing.T) {
			if err := validateLeafCertificatePEM(contents); err == nil {
				t.Fatal("non-canonical leaf certificate PEM accepted")
			}
		})
	}
}

func TestCABundlePEMAllowsOnlyOneOrMoreCertificates(t *testing.T) {
	certificatePEM, keyPEM := testCredentialPEM(t)
	for name, contents := range map[string][]byte{
		"one certificate":  certificatePEM,
		"two certificates": append(append([]byte(nil), certificatePEM...), certificatePEM...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCABundlePEM(contents); err != nil {
				t.Fatalf("valid CA bundle rejected: %v", err)
			}
		})
	}
	rejected := map[string][]byte{
		"empty":               nil,
		"private key":         keyPEM,
		"certificate and key": append(append([]byte(nil), certificatePEM...), keyPEM...),
		"leading garbage":     append([]byte("garbage\n"), certificatePEM...),
		"trailing garbage":    append(append([]byte(nil), certificatePEM...), []byte("garbage")...),
		"invalid DER":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
	}
	for name, contents := range rejected {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCABundlePEM(contents); err == nil {
				t.Fatal("non-canonical CA bundle accepted")
			}
		})
	}
}

func TestPublicCredentialKindRejectsPrivateKeyMaterial(t *testing.T) {
	certificatePEM, keyPEM := testCredentialPEM(t)
	if err := validateCredentialPEM(certificatePEM, PublicCertificate); err != nil {
		t.Fatalf("public certificate rejected: %v", err)
	}
	if err := validateCredentialPEM(keyPEM, PublicCertificate); err == nil {
		t.Fatal("private key accepted as a public credential")
	}
	if err := validateCredentialPEM(certificatePEM, Kind(255)); err == nil {
		t.Fatal("unknown credential kind accepted")
	}
}

func TestPrivateKeyPEMRequiresExactlyOnePKCS8Key(t *testing.T) {
	certificatePEM, keyPEM := testCredentialPEM(t)
	if err := validatePrivateKeyPEM(keyPEM); err != nil {
		t.Fatalf("valid private key rejected: %v", err)
	}
	rejected := map[string][]byte{
		"empty":               nil,
		"two keys":            append(append([]byte(nil), keyPEM...), keyPEM...),
		"certificate":         certificatePEM,
		"key and certificate": append(append([]byte(nil), keyPEM...), certificatePEM...),
		"leading garbage":     append([]byte("garbage\n"), keyPEM...),
		"trailing garbage":    append(append([]byte(nil), keyPEM...), []byte("garbage")...),
		"wrong key label":     pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: []byte("invalid")}),
		"invalid DER":         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}),
	}
	for name, contents := range rejected {
		t.Run(name, func(t *testing.T) {
			if err := validatePrivateKeyPEM(contents); err == nil {
				t.Fatal("non-canonical private key PEM accepted")
			}
		})
	}
}

func TestCredentialLoadersApplyStrictPEMPolicy(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux production policy requires root-owned credential fixtures")
	}
	certificatePEM, keyPEM := testCredentialPEM(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "leaf.crt")
	keyPath := filepath.Join(dir, "leaf.key")
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath, append(append([]byte(nil), certificatePEM...), []byte("garbage")...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(certPath, keyPath, EdgePrivateKey); err == nil {
		t.Fatal("key-pair loader accepted trailing certificate garbage")
	}
	if err := os.WriteFile(caPath, append(append([]byte(nil), certificatePEM...), keyPEM...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertPool(caPath); err == nil {
		t.Fatal("CA loader accepted an embedded private key")
	}
}
