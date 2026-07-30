package credential

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxCredentialSize = 1024 * 1024

// Kind selects the least-permissive filesystem policy appropriate for a
// credential. Private keys permit 0600 root-only staging or an installed 0640
// root-owned key whose group exactly matches the process effective group.
type Kind uint8

const (
	PublicCertificate Kind = iota
	EdgePrivateKey
	RelayPrivateKey
)

// Read validates every existing path component before opening the leaf. The
// component policy makes the lstat/open check stable against non-root writers
// on Linux: all components must be root-owned and group/world non-writable.
func Read(path string, kind Kind) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("credential path must be non-empty, absolute, and canonical")
	}
	leafInfo, err := validateComponents(path, kind)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credential: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened credential: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(leafInfo, openedInfo) {
		return nil, errors.New("credential changed during validation or is not a regular file")
	}
	if err := validatePlatformPolicy(openedInfo, true, kind); err != nil {
		return nil, err
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxCredentialSize+1))
	if err != nil {
		return nil, fmt.Errorf("read credential: %w", err)
	}
	if len(contents) > maxCredentialSize {
		return nil, fmt.Errorf("credential exceeds %d bytes", maxCredentialSize)
	}
	if err := validateCredentialPEM(contents, kind); err != nil {
		return nil, fmt.Errorf("credential PEM rejected: %w", err)
	}
	return contents, nil
}

func LoadKeyPair(certPath, keyPath string, keyKind Kind) (tls.Certificate, error) {
	if keyKind != EdgePrivateKey && keyKind != RelayPrivateKey {
		return tls.Certificate{}, errors.New("private key credential kind is required")
	}
	certPEM, err := Read(certPath, PublicCertificate)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate path rejected: %w", err)
	}
	if err := validateLeafCertificatePEM(certPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("leaf certificate rejected: %w", err)
	}
	keyPEM, err := Read(keyPath, keyKind)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("private key path rejected: %w", err)
	}
	if err := validatePrivateKeyPEM(keyPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("private key rejected: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate/private key tuple rejected: %w", err)
	}
	return pair, nil
}

func LoadCertPool(path string) (*x509.CertPool, error) {
	contents, err := Read(path, PublicCertificate)
	if err != nil {
		return nil, fmt.Errorf("CA path rejected: %w", err)
	}
	certificates, err := parseCABundlePEM(contents)
	if err != nil {
		return nil, fmt.Errorf("CA bundle rejected: %w", err)
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, nil
}

func validateLeafCertificatePEM(contents []byte) error {
	blocks, err := decodeExactPEMBlocks(contents, "CERTIFICATE", 1, 1)
	if err != nil {
		return err
	}
	if _, err := x509.ParseCertificate(blocks[0].Bytes); err != nil {
		return errors.New("certificate DER is invalid")
	}
	return nil
}

func validateCredentialPEM(contents []byte, kind Kind) error {
	switch kind {
	case PublicCertificate:
		_, err := parseCABundlePEM(contents)
		return err
	case EdgePrivateKey, RelayPrivateKey:
		return validatePrivateKeyPEM(contents)
	default:
		return errors.New("unknown credential policy")
	}
}

func parseCABundlePEM(contents []byte) ([]*x509.Certificate, error) {
	blocks, err := decodeExactPEMBlocks(contents, "CERTIFICATE", 1, 0)
	if err != nil {
		return nil, err
	}
	certificates := make([]*x509.Certificate, 0, len(blocks))
	for _, block := range blocks {
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("CA certificate DER is invalid")
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func validatePrivateKeyPEM(contents []byte) error {
	blocks, err := decodeExactPEMBlocks(contents, "PRIVATE KEY", 1, 1)
	if err != nil {
		return err
	}
	if _, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes); err != nil {
		return errors.New("private key is not valid PKCS#8")
	}
	return nil
}

// decodeExactPEMBlocks deliberately does not use the permissive behavior of
// pem.Decode to skip prose or unrelated blocks. Only ASCII whitespace may
// surround the exact block sequence.
func decodeExactPEMBlocks(contents []byte, blockType string, minCount, maxCount int) ([]*pem.Block, error) {
	beginMarker := []byte("-----BEGIN " + blockType + "-----")
	rest := trimPEMWhitespace(contents)
	blocks := make([]*pem.Block, 0, minCount)
	for len(rest) != 0 {
		if !bytes.HasPrefix(rest, beginMarker) || len(rest) == len(beginMarker) ||
			(rest[len(beginMarker)] != '\n' && rest[len(beginMarker)] != '\r') {
			return nil, fmt.Errorf("only %s PEM blocks are permitted", blockType)
		}
		block, remainder := pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("malformed %s PEM block", blockType)
		}
		if block.Type != blockType || len(block.Headers) != 0 {
			return nil, fmt.Errorf("only unadorned %s PEM blocks are permitted", blockType)
		}
		blocks = append(blocks, block)
		if maxCount != 0 && len(blocks) > maxCount {
			return nil, fmt.Errorf("expected at most %d %s PEM block(s)", maxCount, blockType)
		}
		rest = trimPEMWhitespace(remainder)
	}
	if len(blocks) < minCount {
		return nil, fmt.Errorf("expected at least %d %s PEM block(s)", minCount, blockType)
	}
	return blocks, nil
}

func trimPEMWhitespace(contents []byte) []byte {
	return bytes.Trim(contents, " \t\r\n")
}

func validateComponents(path string, kind Kind) (os.FileInfo, error) {
	current := filepath.Clean(path)
	leaf := true
	var leafInfo os.FileInfo
	type component struct {
		info os.FileInfo
		leaf bool
	}
	components := make([]component, 0, 8)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("lstat credential component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("credential path contains a symbolic link")
		}
		if leaf {
			if !info.Mode().IsRegular() {
				return nil, errors.New("credential leaf is not a regular file")
			}
			leafInfo = info
		} else if !info.IsDir() {
			return nil, errors.New("credential parent component is not a directory")
		}
		components = append(components, component{info: info, leaf: leaf})
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
		leaf = false
	}
	for _, part := range components {
		if err := validatePlatformPolicy(part.info, part.leaf, kind); err != nil {
			return nil, err
		}
	}
	return leafInfo, nil
}
