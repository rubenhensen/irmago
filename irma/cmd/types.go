package cmd

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"

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

		attributeTypes := irmaconfig.AttributeTypes

		managerIssuerCredFolder(attributeTypes, dest)

		return nil
	},
}

func init() {
	schemeCmd.AddCommand(typesCmd)
}

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
