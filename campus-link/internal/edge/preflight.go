package edge

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/credential"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

type validatedTLSMaterial struct {
	controlTLS   *tls.Config
	dataTLS      *tls.Config
	localControl identity.Verified
	localData    identity.Verified
}

// ValidateConfig performs the complete credential and TLS configuration
// preflight without resolving or dialing an address, opening a listener, or
// creating a TUN device.
func (r *Runner) ValidateConfig() error {
	_, _, err := r.validatedTLSConfigs()
	return err
}

func (r *Runner) validatedTLSConfigs() (*tls.Config, *tls.Config, error) {
	material, err := r.validatedTLSMaterial(time.Now())
	if err != nil {
		return nil, nil, err
	}
	return material.controlTLS, material.dataTLS, nil
}

func (r *Runner) validatedTLSMaterial(now time.Time) (validatedTLSMaterial, error) {
	controlCertificate, err := credential.LoadKeyPair(r.cfg.ControlCert, r.cfg.ControlKey, credential.EdgePrivateKey)
	if err != nil {
		return validatedTLSMaterial{}, fmt.Errorf("control credential: %w", err)
	}
	controlRoots, err := credential.LoadCertPool(r.cfg.ControlCA)
	if err != nil {
		return validatedTLSMaterial{}, fmt.Errorf("control root: %w", err)
	}
	dataCertificate, err := credential.LoadKeyPair(r.cfg.DataCert, r.cfg.DataKey, credential.EdgePrivateKey)
	if err != nil {
		return validatedTLSMaterial{}, fmt.Errorf("data credential: %w", err)
	}
	dataRoots, err := credential.LoadCertPool(r.cfg.DataCA)
	if err != nil {
		return validatedTLSMaterial{}, fmt.Errorf("data root: %w", err)
	}
	localControl, localData, err := r.verifyLocalIdentities(controlCertificate, controlRoots, dataCertificate, dataRoots, now)
	if err != nil {
		return validatedTLSMaterial{}, err
	}
	return validatedTLSMaterial{
		controlTLS:   clientTLSFromMaterial(controlCertificate, controlRoots, r.cfg.ControlServerName, r.controlRequirements),
		dataTLS:      r.dataTLSFromMaterial(dataCertificate, dataRoots),
		localControl: localControl, localData: localData,
	}, nil
}

func (r *Runner) validateLocalIdentities(controlCertificate tls.Certificate, controlRoots *x509.CertPool, dataCertificate tls.Certificate, dataRoots *x509.CertPool) error {
	_, _, err := r.verifyLocalIdentities(controlCertificate, controlRoots, dataCertificate, dataRoots, time.Now())
	return err
}

func (r *Runner) verifyLocalIdentities(controlCertificate tls.Certificate, controlRoots *x509.CertPool, dataCertificate tls.Certificate, dataRoots *x509.CertPool, now time.Time) (identity.Verified, identity.Verified, error) {
	localControlURI, err := expectedIdentityURI(r.cfg.Circuit, r.cfg.Site, "control")
	if err != nil {
		return identity.Verified{}, identity.Verified{}, err
	}
	localControlRequirements, err := authorizationRequirements(
		r.cfg.LocalControlIdentity, localControlURI, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	if err != nil {
		return identity.Verified{}, identity.Verified{}, fmt.Errorf("invalid local control identity authorization: %w", err)
	}
	localControlRequirements.Now = now
	localDataURI, err := expectedIdentityURI(r.cfg.Circuit, r.cfg.Site, "data")
	if err != nil {
		return identity.Verified{}, identity.Verified{}, err
	}
	localDataRequirements, err := authorizationRequirements(
		r.cfg.LocalDataIdentity, localDataURI,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	)
	if err != nil {
		return identity.Verified{}, identity.Verified{}, fmt.Errorf("invalid local data identity authorization: %w", err)
	}
	localDataRequirements.Now = now
	if err := identity.ValidateAuthorizationIsolation(
		localControlRequirements, localDataRequirements, r.controlRequirements, r.dataRequirements,
	); err != nil {
		return identity.Verified{}, identity.Verified{}, fmt.Errorf("edge identity authorization isolation: %w", err)
	}
	localControl, err := identity.VerifyLocalCertificate(controlCertificate, controlRoots, localControlRequirements, "")
	if err != nil {
		return identity.Verified{}, identity.Verified{}, fmt.Errorf("local control identity: %w", err)
	}
	localDataDNSName := r.cfg.Site + ".campus-link"
	localData, err := identity.VerifyLocalCertificate(dataCertificate, dataRoots, localDataRequirements, localDataDNSName)
	if err != nil {
		return identity.Verified{}, identity.Verified{}, fmt.Errorf("local data identity: %w", err)
	}
	if _, err := identity.SessionDeadline(now, localControl, localData); err != nil {
		return identity.Verified{}, identity.Verified{}, fmt.Errorf("local identity lifetime: %w", err)
	}
	authorizedPins := make([]string, 0, len(r.controlRequirements.Pins)+len(r.dataRequirements.Pins))
	authorizedPins = append(authorizedPins, r.controlRequirements.Pins...)
	authorizedPins = append(authorizedPins, r.dataRequirements.Pins...)
	if err := identity.ValidateKeyIsolation(
		[]tls.Certificate{controlCertificate, dataCertificate}, authorizedPins...,
	); err != nil {
		return identity.Verified{}, identity.Verified{}, fmt.Errorf("edge identity key isolation: %w", err)
	}
	return localControl, localData, nil
}
