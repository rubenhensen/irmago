package irma

import (
	"encoding/json"
	"github.com/privacybydesign/gabi"
	ariesvc "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
	Type            string 			`json:"type"`
	Created         string          `json:"created"`
	ProofMsg 		interface{}		`json:"proofMsg"`
}

type VerifiableCredential struct {
	LDContext          [2]string                `json:"@context"`
	Schema 			   []VCSchema				`json:"credentialSchema,omitempty"`
	Type               []string                 `json:"type"`
	Issuer             string                   `json:"issuer,omitempty"`
	IssuanceDate       string                   `json:"issuanceDate,omitempty"`
	ExpirationDate	   string					`json:"expirationDate,omitempty"`
	CredentialSubjects []map[string]interface{} `json:"credentialSubject"`
	Proof              VCProof                  `json:"proof"`
}

type VerifiablePresentation struct {
	LDContext 			[2]string           	`json:"@context"`
	Type      			[]string            	`json:"type"` // must include VerifiablePresentation
	DerivedCredentials 	[]VerifiableCredential 	`json:"verifiableCredential"`
	Proof    			VCProof 				`json:"proof"`
}

type VCPresentationProof struct {
	Type            string      `json:"type"`
	Created         string      `json:"created"`
	DisclosureProof gabi.ProofList `json:"gabi"`
}

type VCSchema struct {
	Type            string      `json:"type"`	// type name
	Identifier		string 		`json:"id"`		// URL resolving to schema
}


func NewVCTranslatedString(attr string) TranslatedString {
	return map[string]string{
		"rawValue":   attr, // raw value
		"en": attr,
		"nl": attr,
	}
}

func (vc *VerifiableCredential) Validate() error {
	vcByte, _ := json.Marshal(vc)
	_, _, err := ariesvc.NewCredential(vcByte)
	if err != nil {
		return err
	}
	return nil
}

func (vp *VerifiablePresentation) Validate() error {
	vpByte, _ := json.Marshal(vp)
	_, err := ariesvc.NewPresentation(vpByte)
	if err != nil {
		return err
	}
	return nil
}

// Boolean to tell IRMA app to request VC (via VC header set to "yes" to indicate to server to return a VC), and process it via ConstructVerifiableCredential
var IssueVC = false


