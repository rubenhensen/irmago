package irma

import (
	"encoding/json"
	"fmt"
	"net/http"

	ariesvc "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/privacybydesign/gabi"
)

type VCType map[string]interface{}

type VCAttributeType struct {
	Type    string `json:"@type"`
	Comment string `json:"comment"`
	ID      string `json:"@id"`
}

type VCSubject struct {
	Attributes map[string]TranslatedString `json:"attributes"`
}

type VCProof struct {
	Type     string      `json:"type"`
	Created  string      `json:"created"`
	ProofMsg interface{} `json:"proofMsg"`
}
type VerifiableCredential struct {
	LDContext          [2]string              `json:"@context"`
	Schema             []VCSchema             `json:"credentialSchema,omitempty"`
	Type               []string               `json:"type"`
	Id                 string                 `json:"id,omitempty"`
	Issuer             string                 `json:"issuer,omitempty"`
	IssuanceDate       string                 `json:"issuanceDate,omitempty"`
	ExpirationDate     string                 `json:"expirationDate,omitempty"`
	CredentialSubjects map[string]interface{} `json:"credentialSubject"`
	Proof              VCProof                `json:"proof,omitempty"`
}

type VerifiablePresentation struct {
	LDContext          [2]string              `json:"@context"`
	Type               []string               `json:"type"` // must include VerifiablePresentation
	DerivedCredentials []VerifiableCredential `json:"verifiableCredential"`
	Proof              VCProof                `json:"proof"`
}

type VCPresentationProof struct {
	Type            string         `json:"type"`
	Created         string         `json:"created"`
	DisclosureProof gabi.ProofList `json:"gabi"`
}

type VCSchema struct {
	Type       string `json:"type"` // type name
	Identifier string `json:"id"`   // URL resolving to schema
}

func (vc VerifiableCredential) Validate() error {

	client := &http.Client{}
	nl := ld.NewDefaultDocumentLoader(client)

	vcByte, err := json.Marshal(vc)
	if err != nil {
		panic(fmt.Errorf("failed to decode marshal json: %w", err))
	}

	_, err = ariesvc.ParseCredential(
		vcByte,
		ariesvc.WithDisabledProofCheck(),
		ariesvc.WithJSONLDDocumentLoader(nl))
	if err != nil {
		panic(fmt.Errorf("failed to decode VC JWS: %w", err))
	}
	return nil
}

func (vp *VerifiablePresentation) Validate() error {
	vpByte, _ := json.Marshal(vp)
	_, err := ariesvc.ParsePresentation(vpByte)
	if err != nil {
		return err
	}
	return nil
}
