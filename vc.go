package irma

import (
	"encoding/json"
	"fmt"
	"net/http"

	ariesvc "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/privacybydesign/gabi"
)

const (
	LDVerifiableCredential = "https://www.w3.org/2018/credentials/v1"
	ProofType              = "IRMAZKPPresentationProofv1"
	VCServerURL            = "http://192.168.2.100:8089/" // Ruben TODO: temporary!
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
	LDContext          [2]string                `json:"@context"`
	Schema             []VCSchema               `json:"credentialSchema,omitempty"`
	Type               []string                 `json:"type"`
	Id                 string                   `json:"id,omitempty"`
	Issuer             string                   `json:"issuer,omitempty"`
	IssuanceDate       string                   `json:"issuanceDate,omitempty"`
	ExpirationDate     string                   `json:"expirationDate,omitempty"`
	CredentialSubjects []map[string]interface{} `json:"credentialSubject"`
	Proof              VCProof                  `json:"proof,omitempty"`
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

func (vp VerifiablePresentation) Validate() error {
	// Ruben TODO: create VP validator
	return nil
}

func NewVCTranslatedString(attr string) TranslatedString {
	return map[string]string{
		"rawValue": attr, // raw value
		"en":       attr,
		"nl":       attr,
	}
}

// Types required to compute the credentialSchema

type AnyOf struct {
	Req []string `json:"required"`
}

type Required struct {
	Req []string `json:"required"`
}

type Attribute struct {
	Ref string `json:"$ref"`
}

type CredType struct {
	AdditionalProperties bool                 `json:"additionalProperties"`
	AnyOf                []AnyOf              `json:"anyOf"`
	Description          string               `json:"description"`
	Properties           map[string]Attribute `json:"properties"`
	Type                 string               `json:"type"`
}

type Type string

type En struct {
	Type `json:"type"`
}

type Nl struct {
	Type `json:"type"`
}

type RawValue struct {
	Type `json:"type"`
}

type Properties struct {
	En       `json:"en"`
	Nl       `json:"nl"`
	RawValue `json:"rawValue"`
}

type TranslatedStringSchema struct {
	Properties `json:"properties"`
	Required   []string `json:"required"`
	Type       string   `json:"type"`
}

type DefaultSchema struct {
	Type  string `json:"type"`
	Items []Item `json:"items"`
}

type Item struct {
	AdditionalProperties bool `json:"additionalProperties"`
	Properties           struct {
		CredType struct {
			Ref string `json:"$ref"`
		} `json:"credType"`
	} `json:"properties"`
	Required []string `json:"required"`
}

type Definitions struct {
	CredType               `json:"credType"`
	TranslatedStringSchema `json:"translatedString"`
}
