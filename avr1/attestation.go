package avr1

import "github.com/verirelay/protocol/internal/wire"

// Attestation identifiers and encodings accompany AVRVersion in the response
// from GET /v1/avr/attestation. AttestationReportSize is the length of a raw
// AMD SEV-SNP attestation report.
const (
	AttestationTEETypeSEVSNP        = "sev-snp"
	AttestationEvidenceFormat       = "amd-sev-snp-report/1"
	AttestationEndorsementsFormat   = "amd-sev-snp-cert-chain/1"
	AttestationEndorsementsEncoding = "base64url-der"
	AttestationBindingRuleV1        = "verirelay-avr-report-data/1"
	AttestationReportDataEncoding   = "raw-64-bytes"
	AttestationPublicKeyEncoding    = "base64url-unpadded-ed25519-raw-32-bytes"
	AttestationNonceEncoding        = "base64url-unpadded-raw-32-bytes"
	AttestationReportSize           = 1184
)

// AttestationResponse is the nonce-bound response from GET /v1/avr/attestation.
// Source and LaunchProfile are disclosures, not a Guest Manifest. Bootstrap is
// the base64url of the exact Bootstrap bytes, whose SHA-256 is the report's
// HOST_DATA; it is empty in development mode.
type AttestationResponse struct {
	Version                 string                   `json:"version"`
	TEEType                 string                   `json:"tee_type"`
	Evidence                AttestationEvidence      `json:"evidence"`
	Endorsements            AttestationEndorsements  `json:"endorsements"`
	Nonce                   string                   `json:"nonce"`
	ReceiptSigningPublicKey string                   `json:"receipt_signing_public_key"`
	KeyID                   string                   `json:"key_id"`
	KeyBinding              AttestationKeyBinding    `json:"key_binding"`
	Source                  AttestationSource        `json:"source"`
	LaunchProfile           AttestationLaunchProfile `json:"launch_profile"`
	Bootstrap               string                   `json:"bootstrap,omitempty"`
}

// AttestationEvidence carries the base64url of the raw AMD SEV-SNP attestation
// report in Report.
type AttestationEvidence struct {
	Format     string `json:"format"`
	Report     string `json:"report"`
	ReportData string `json:"report_data"`
}

// AttestationEndorsements carries base64url DER certificates.
type AttestationEndorsements struct {
	Format   string `json:"format"`
	Encoding string `json:"encoding"`
	VCEK     string `json:"vcek,omitempty"`
	VLEK     string `json:"vlek,omitempty"`
	ASK      string `json:"ask"`
	ARK      string `json:"ark"`
}

// AttestationKeyBinding describes the ReportDataAVR1 binding and input encodings.
type AttestationKeyBinding struct {
	Rule               string `json:"rule"`
	ProtocolVersion    string `json:"protocol_version"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	ReportDataSHA512   string `json:"report_data_sha512"`
	ReportDataEncoding string `json:"report_data_encoding"`
	PublicKeyEncoding  string `json:"public_key_encoding"`
	NonceEncoding      string `json:"nonce_encoding"`
}

// AttestationSource discloses the Guest's component source identities.
type AttestationSource struct {
	VeriRelay AttestationSourceRef `json:"verirelay"`
	VeriForge AttestationSourceRef `json:"veriforge"`
}

// AttestationSourceRef is a disclosed repository URL and commit.
type AttestationSourceRef struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

// AttestationLaunchProfile discloses the Guest's launch parameters.
type AttestationLaunchProfile struct {
	Version            string `json:"version"`
	MeasurementProfile string `json:"measurement_profile"`
	VCPUType           string `json:"vcpu_type"`
	GuestFeatures      string `json:"guest_features"`
	KernelHashes       bool   `json:"kernel_hashes"`
	KernelAppend       string `json:"kernel_append"`
}

// DecodeAttestationResponse decodes an attestation response leniently: data
// must be one JSON object without duplicate keys at any depth, and unknown
// fields are ignored. It does not validate required fields, identifiers,
// encodings, certificates, evidence, policy or disclosure claims.
func DecodeAttestationResponse(data []byte) (AttestationResponse, error) {
	var response AttestationResponse
	if err := wire.DecodeLenient(data, &response); err != nil {
		return AttestationResponse{}, err
	}
	return response, nil
}
