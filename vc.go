package irma

import (
	"encoding/json"
	"errors"
	"net"

	ariesvc "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
	LDContext          [2]string                `json:"@context"`
	Schema             []VCSchema               `json:"credentialSchema,omitempty"`
	Type               []string                 `json:"type"`
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

func NewVCTranslatedString(attr string) TranslatedString {
	return map[string]string{
		"rawValue": attr, // raw value
		"en":       attr,
		"nl":       attr,
	}
}

func (vc *VerifiableCredential) Validate() error {
	vcByte, _ := json.Marshal(vc)
	_, err := ariesvc.ParseCredential(vcByte)
	if err != nil {
		return err
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

// Boolean to tell IRMA app to compute a VC commitment (and server detects type of commitment to decide if to compute IRMA credential, or VC)
// Process it via ConstructVerifiableCredential
var IssueVC = true
var VCServerURL = "http://192.168.2.100:8089/"

func ExternalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}
