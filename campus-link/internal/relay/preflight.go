package relay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/credential"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

const relayControlDNSName = "gz.campus-link"

type validatedTLSMaterial struct {
	config       *tls.Config
	localControl identity.Verified
}

// ValidateConfig performs the complete credential and TLS configuration
// preflight using the paths carried by this Server's supplied configuration.
// It does not resolve or bind either listen address.
func (s *Server) ValidateConfig() error {
	_, err := s.validatedTLSConfig()
	return err
}

func (s *Server) validatedTLSConfig() (*tls.Config, error) {
	material, err := s.validatedTLSMaterial(time.Now())
	if err != nil {
		return nil, err
	}
	return material.config, nil
}

func (s *Server) validatedTLSMaterial(now time.Time) (validatedTLSMaterial, error) {
	certificate, err := credential.LoadKeyPair(s.cfg.ControlCert, s.cfg.ControlKey, credential.RelayPrivateKey)
	if err != nil {
		return validatedTLSMaterial{}, fmt.Errorf("relay control credential: %w", err)
	}
	roots, err := credential.LoadCertPool(s.cfg.ControlCA)
	if err != nil {
		return validatedTLSMaterial{}, fmt.Errorf("relay control root: %w", err)
	}
	localControl, err := s.verifyLocalIdentity(certificate, roots, now)
	if err != nil {
		return validatedTLSMaterial{}, err
	}
	return validatedTLSMaterial{config: s.relayTLSFromMaterial(certificate, roots), localControl: localControl}, nil
}

func (s *Server) validateLocalIdentity(certificate tls.Certificate, roots *x509.CertPool) error {
	_, err := s.verifyLocalIdentity(certificate, roots, time.Now())
	return err
}

func (s *Server) verifyLocalIdentity(certificate tls.Certificate, roots *x509.CertPool, now time.Time) (identity.Verified, error) {
	localURI, err := expectedIdentityURI(s.cfg.Circuit, "relay", "control")
	if err != nil {
		return identity.Verified{}, err
	}
	requirements, err := authorizationRequirements(
		s.cfg.LocalControlIdentity, localURI, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	if err != nil {
		return identity.Verified{}, fmt.Errorf("invalid local relay control authorization: %w", err)
	}
	requirements.Now = now
	visibleRequirements := []identity.Requirements{requirements}
	for _, site := range []string{"site-a", "site-b"} {
		peerRequirements, ok := s.controlRequirements[site]
		if !ok {
			return identity.Verified{}, errors.New("relay control authorization is incomplete")
		}
		visibleRequirements = append(visibleRequirements, peerRequirements)
	}
	if err := identity.ValidateAuthorizationIsolation(visibleRequirements...); err != nil {
		return identity.Verified{}, fmt.Errorf("relay identity authorization isolation: %w", err)
	}
	verified, err := identity.VerifyLocalCertificate(certificate, roots, requirements, relayControlDNSName)
	if err != nil {
		return identity.Verified{}, fmt.Errorf("local relay control identity: %w", err)
	}
	if _, err := identity.SessionDeadline(now, verified); err != nil {
		return identity.Verified{}, fmt.Errorf("local relay control lifetime: %w", err)
	}
	authorizedPins := make([]string, 0, 4)
	for _, site := range []string{"site-a", "site-b"} {
		requirements, ok := s.controlRequirements[site]
		if !ok {
			return identity.Verified{}, errors.New("relay control authorization is incomplete")
		}
		authorizedPins = append(authorizedPins, requirements.Pins...)
	}
	if err := identity.ValidateKeyIsolation([]tls.Certificate{certificate}, authorizedPins...); err != nil {
		return identity.Verified{}, fmt.Errorf("relay identity key isolation: %w", err)
	}
	return verified, nil
}
