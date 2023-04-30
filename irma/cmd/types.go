package cmd

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"

	xj "github.com/basgys/goxml2json"
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
)

// var requestorServerPort = 48682
// var requestorServerURL = "http://localhost:48682"

// signCmd represents the sign command
var typesCmd = &cobra.Command{
	Use:   "types [dest]",
	Short: "Export all types to JSON-LD",
	Long:  `Loads a XML scheme manager from a URL, then iterates through all the types to convert them to JSON-LD`,
	Args:  cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			dest string
			err  error
		)
		wd, err := os.Getwd()
		if err != nil {
			return errors.WrapPrefix(err, "Error getting working directory", 0)
		}

		switch len(args) {
		case 0:
			dest = filepath.Join(wd, "schemeTypes")
			if err = common.AssertPathExists(filepath.Join(wd, "schemeTypes")); err != nil {
				if err := os.Mkdir(dest, os.ModePerm); err != nil {
					return errors.WrapPrefix(err, "Error creating JSON directory", 0)
				}
			}
		case 1:
			dest, err = filepath.Abs(args[0])
			if err != nil {
				return errors.WrapPrefix(err, "Error turning input to filepath", 0)
			}
			if err = common.AssertPathExists(dest); err != nil {
				if err := os.Mkdir(dest, os.ModePerm); err != nil {
					return errors.WrapPrefix(err, "Error creating JSON directory", 0)
				}
			}
		}

		irmaconfig, err := irma.NewConfiguration(irma.DefaultSchemesPath(), irma.ConfigurationOptions{})
		if err != nil {
			return err
		}

		if len(irmaconfig.SchemeManagers) == 0 {
			if err = irmaconfig.DownloadDefaultSchemes(); err != nil {
				return err
			}
		}

		// attributeTypes := irmaconfig.AttributeTypes

		generateSchemaValidator(irmaconfig, dest)
		// managerIssuerCredFolder(attributeTypes, dest)

		return nil
	},
}

func init() {
	schemeCmd.AddCommand(typesCmd)
}

func generateSchemaValidator(conf *irma.Configuration, dest string) error {

	for _, cred := range conf.CredentialTypes {
		var schema irma.DefaultSchema
		var credType irma.CredType
		var definitions irma.Definitions
		var items []irma.Item
		var item irma.Item
		var translatedString = irma.TranslatedStringSchema{
			Required:   []string{"rawValue", "en", "nl"},
			Properties: irma.Properties{irma.En{Type: "string"}, irma.Nl{Type: "string"}, irma.RawValue{Type: "string"}},
			Type:       "object",
		}

		// create sm folder
		smFolder := filepath.Join(dest, cred.SchemeManagerID)
		// Check and create schememanager folder
		if err := common.AssertPathExists(smFolder); err != nil {
			if err := os.Mkdir(smFolder, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating directory", 0)
			}
		}

		issuerFolder := filepath.Join(smFolder, cred.IssuerID)
		// Check and create issuer folder
		if err := common.AssertPathExists(issuerFolder); err != nil {
			if err := os.Mkdir(issuerFolder, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating directory", 0)
			}
		}

		credFolder := filepath.Join(issuerFolder, cred.ID)

		// Check and create credentials folder
		if err := common.AssertPathExists(credFolder); err != nil {
			if err := os.Mkdir(credFolder, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating directory", 0)
			}
		}

		// create jsonld
		credID := irma.NewCredentialTypeIdentifier(cred.SchemeManagerID + "." + cred.IssuerID + "." + cred.ID)
		credentialType := conf.CredentialTypes[credID]
		credType.Properties = map[string]irma.Attribute{}

		for _, attr := range credentialType.AttributeTypes {
			var jsAttr irma.Attribute
			var anyOf irma.AnyOf

			anyOf.Req = append(anyOf.Req, attr.ID)
			credType.AnyOf = append(credType.AnyOf, anyOf)

			jsAttr.Ref = "#/definitions/translatedString"
			credType.Properties[attr.ID] = jsAttr
		}

		schema.Type = "array"

		credType.Type = "object"
		credType.Description = credentialType.Description["en"]

		definitions.TranslatedStringSchema = translatedString
		definitions.CredType = credType

		item.Properties.CredType.Ref = "#/definitions/" + credentialType.ID
		item.Required = []string{credentialType.ID}
		items = append(items, item)
		schema.Items = items

		definitionsByte, err := json.Marshal(definitions)

		out, err := json.Marshal(schema)
		if err != nil {
			panic(err)
		}

		outString := strings.Replace(string(out), "credType", credentialType.ID, -1)
		outString = jsonPrettyPrint(outString)

		outString = strings.Replace(string(defaultSchema), "$subject", outString, -1)

		definitions2 := strings.Replace(string(definitionsByte), "credType", credentialType.ID, -1)
		definitions2 = jsonPrettyPrint(definitions2)
		definitions2 = strings.TrimSuffix(definitions2, "}")
		definitions2 = strings.TrimPrefix(definitions2, "{")

		outString = strings.Replace(outString, "$definition", jsonPrettyPrint(string(definitions2)), -1)
		errors.WrapPrefix(err, "Error creating directory", 0)

		// save to file
		if err := os.WriteFile(filepath.Join(credFolder, "schema.jsonld"), []byte(outString), 0644); err != nil {
			return errors.WrapPrefix(err, "Error writing file", 0)
		}
	}
	return nil
}

func jsonPrettyPrint(in string) string {
	var out bytes.Buffer
	err := json.Indent(&out, []byte(in), "", "\t")
	if err != nil {
		return in
	}
	return out.String()
}

const defaultSchema = `{
	"required": [
	  "@context",
	  "type",
	  "credentialSubject",
	  "issuer",
	  "issuanceDate"
	],
	"properties": {
	  "@context": {
		"type": "array",
		"items": [
		  {
			"type": "string",
			"pattern": "^https://www.w3.org/2018/credentials/v1$"
		  }
		],
		"uniqueItems": true,
		"additionalItems": {
		  "oneOf": [
			{
			  "type": "object"
			},
			{
			  "type": "string"
			}
		  ]
		}
	  },
	  "id": {
		"type": "string",
		"format": "uri"
	  },
	  "type": {
		"oneOf": [
		  {
			"type": "array",
			"items": [
			  {
				"type": "string",
				"pattern": "^VerifiableCredential$"
			  }
			]
		  },
		  {
			"type": "string",
			"pattern": "^VerifiableCredential$"
		  }
		],
		"additionalItems": {
		  "type": "string"
		},
		"minItems": 2
	  },
	  "credentialSubject": 
		  $subject
	  ,
	  "issuer": {
		"anyOf": [
		  {
			"type": "string",
			"format": "uri"
		  },
		  {
			"type": "object",
			"required": [
			  "id"
			],
			"properties": {
			  "id": {
				"type": "string"
			  }
			}
		  }
		]
	  },
	  "issuanceDate": {
		"$ref": "#/definitions/timestamp"
	  },
	  "proof": {
		"type": "object",
		"required": [
		  "type"
		],
		"properties": {
		  "type": {
			"type": "string"
		  }
		}
	  },
	  "expirationDate": {
		"$ref": "#/definitions/timestamp"
	  },
	  "credentialStatus": {
		"$ref": "#/definitions/typedID"
	  },
	  "credentialSchema": {
		"$ref": "#/definitions/typedIDs"
	  },
	  "evidence": {
		"$ref": "#/definitions/typedIDs"
	  },
	  "refreshService": {
		"$ref": "#/definitions/typedID"
	  }
	},
	"definitions": {
	  "timestamp": {
		"type": "string",
		"pattern": "\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d:[0-5]\\d:[0-5]\\dZ"
	  },
	  "typedID": {
		"type": "object",
		"required": [
		  "id",
		  "type"
		],
		"properties": {
		  "id": {
			"type": "string",
			"format": "uri"
		  },
		  "type": {
			"anyOf": [
			  {
				"type": "string"
			  },
			  {
				"type": "array",
				"items": {
				  "type": "string"
				}
			  }
			]
		  }
		}
	  },
	  "typedIDs": {
		"anyOf": [
		  {
			"$ref": "#/definitions/typedID"
		  },
		  {
			"type": "array",
			"items": {
			  "$ref": "#/definitions/typedID"
			}
		  }
		]
	  },
	  $definition
	}
  }
  `

func managerIssuerCredFolder(attributeTypes map[irma.AttributeTypeIdentifier]*irma.AttributeType, dest string) error {
	var err error

	for _, val := range attributeTypes {
		smFolder := filepath.Join(dest, val.SchemeManagerID)
		// Check and create schememanager folder
		if err = common.AssertPathExists(smFolder); err != nil {
			if err := os.Mkdir(smFolder, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating directory", 0)
			}
		}

		issuerFolder := filepath.Join(smFolder, val.IssuerID)
		// Check and create issuer folder
		if err = common.AssertPathExists(issuerFolder); err != nil {
			if err := os.Mkdir(issuerFolder, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating directory", 0)
			}
		}

		credFolder := filepath.Join(issuerFolder, val.CredentialTypeID)
		// Check and create credentials folder
		if err = common.AssertPathExists(credFolder); err != nil {
			if err := os.Mkdir(credFolder, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating directory", 0)
			}
		}

		attrFolder := filepath.Join(credFolder, val.ID)
		// Check and create credentials folder
		if err = common.AssertPathExists(attrFolder); err != nil {
			if err := os.Mkdir(attrFolder, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating directory", 0)
			}
		}

		xmlFile, err := xml.Marshal(val)
		if err != nil {
			return err
		}
		xmlReader := bytes.NewReader(xmlFile)

		// Decode XML document
		root := &xj.Node{}
		err = xj.NewDecoder(xmlReader, xj.WithTypeConverter(xj.Float, xj.Bool, xj.Int, xj.Null), xj.WithAttrPrefix("")).Decode(root)
		if err != nil {
			return err
		}
		RemoveInterKey(root, "AttributeType")
		RemoveAttr(root, "AttributeType")
		AddAttr(root, "", "@type", "AttributeType")

		AddAttr(root, "", "@context", Context+"context.jsonld")
		// // Taken from containing CredentialType
		// CredentialTypeID string `xml:"-"`
		// IssuerID         string `xml:"-"`
		// SchemeManagerID  string `xml:"-"`

		// // Replace ID with @id
		// val, err := GetAttr(root, "ID")
		// if err != nil {
		// 	return errors.New("Could not get attribute")
		// }
		RemoveAttr(root, "id")
		RemoveAttr(root, "attr")
		AddAttr(root, "", "@id", SchemeURL+val.SchemeManagerID+"/"+val.IssuerID+"/"+val.CredentialTypeID+"/"+val.ID+"/description.jsonld")

		// Replace schememanager val with {@id: IRI}
		node := &xj.Node{}
		iri := SchemeURL + val.SchemeManagerID + "/" + val.IssuerID + "/" + val.CredentialTypeID + "/description.jsonld"
		AddAttr(node, "", "@id", iri)
		AddNode(root, "", "CredentialTypeID", node)

		// Replace schememanager val with {@id: IRI}
		node = &xj.Node{}
		iri = SchemeURL + val.SchemeManagerID + "/" + val.IssuerID + "/description.jsonld"
		AddAttr(node, "", "@id", iri)
		AddNode(root, "", "IssuerID", node)

		// Replace schememanager val with {@id: IRI}
		node = &xj.Node{}
		iri = SchemeURL + val.SchemeManagerID + "/description.jsonld"
		AddAttr(node, "", "@id", iri)
		AddNode(root, "", "SchemeManagerID", node)

		// if err != nil {
		// 	return errors.New("Could not get attribute")
		// }
		// RemoveAttr(root, "SchemeManager")
		// AddNode(root, "Issuer", "SchemeManager", node)

		// Then encode it in JSON
		buf := new(bytes.Buffer)
		e := xj.NewEncoder(buf, xj.WithTypeConverter(xj.Float, xj.Bool, xj.Int, xj.Null), xj.WithAttrPrefix(""))
		err = e.Encode(root)
		if err != nil {
			return err
		}

		if err != nil {
			return errors.WrapPrefix(err, "Error creating json", 0)
		}

		// Pretty format JSON
		prettyJson, err := PrettyString(buf.String())
		if err != nil {
			return errors.WrapPrefix(err, "Error pretty printing json", 0)
		}

		// Write to file
		bts := []byte(prettyJson)
		if err := os.WriteFile(filepath.Join(attrFolder, "description.jsonld"), bts, 0644); err != nil {
			return errors.WrapPrefix(err, "Failed to write description", 0)
		}
	}
	return nil
}

func getUrl(id string) string {
	if id == "irma-demo" {
		return SchemeURL + "irma-demo"
	}
	if id == "pbdf" {
		return SchemeURL + "pbdf"
	}
	panic("No known id")
}
