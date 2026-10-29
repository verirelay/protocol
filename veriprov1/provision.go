package veriprov1

// ProvisionRequest is the provision request body. AttestationReport is the
// base64url of the raw AMD SEV-SNP attestation report, whose REPORT_DATA is
// ReportData of the challenge nonce and ProvisioningPublicKey.
type ProvisionRequest struct {
	ChallengeID           string `json:"challenge_id"`
	ProvisioningPublicKey string `json:"provisioning_public_key"`
	AttestationReport     string `json:"attestation_report"`
}

// Validate checks the challenge ID, an X25519PublicKeySize-byte
// provisioning_public_key, and an AttestationReportSize-byte
// attestation_report.
func (request ProvisionRequest) Validate() error {
	if err := validateChallengeID(request.ChallengeID); err != nil {
		return err
	}
	if _, err := DecodeBase64URL(request.ProvisioningPublicKey, "provisioning_public_key", X25519PublicKeySize); err != nil {
		return err
	}
	if _, err := DecodeBase64URL(request.AttestationReport, "attestation_report", AttestationReportSize); err != nil {
		return err
	}
	return nil
}

// ProvisionResponse is the provision response body.
type ProvisionResponse struct {
	Envelope HPKEEnvelope `json:"envelope"`
}

// Validate checks Envelope, including that its signature is present and
// well-formed. It does not verify the signature; call VerifyEnvelopeSignature.
func (response ProvisionResponse) Validate() error {
	return response.Envelope.validate()
}
