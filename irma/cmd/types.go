package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"

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
		// flags := cmd.Flags()
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
		v1 := filepath.Join(dest, "v1")
		if err = common.AssertPathExists(v1); err != nil {
			if err := os.Mkdir(v1, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating JSON directory", 0)
			}
		}
		for _, val := range attributeTypes {
			smFolder := filepath.Join(v1, val.SchemeManagerID)
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

			// wd, err := os.Getwd()
			// if err != nil {
			// 	die("Failed to get wd", err)
			// }

			// flags := typesCmd.Flags()
			// flags.StringP("url", "u", "https://privacybydesign.foundation/schememanager/pbdf", "External URL to scheme manager.")
			// flags.StringP("src", "s", wd, "Filepath to the scheme manager where all types should be exported from. Defaults to <working-directory>.")
			// flags.StringP("dest", "d", filepath.Join(wd, "typeScheme"), "Filepath to destination folder types should be exported to. Defaults to <working-directory>/typeScheme")
			buf, err := json.Marshal(val)
			if err != nil {
				return errors.WrapPrefix(err, "Error creating json", 0)
			}

			// Pretty format JSON
			prettyJson, err := PrettyString(string(buf))
			if err != nil {
				return errors.WrapPrefix(err, "Error pretty printing json", 0)
			}

			// Write to file
			bts := []byte(prettyJson)
			if err := os.WriteFile(filepath.Join(issuerFolder, val.CredentialTypeID+".jsonld"), bts, 0644); err != nil {
				return errors.WrapPrefix(err, "Failed to write description", 0)
			}
		}

		v2 := filepath.Join(dest, "v2")
		if err = common.AssertPathExists(v2); err != nil {
			if err := os.Mkdir(v2, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating JSON directory", 0)
			}
		}
		for _, val := range attributeTypes {
			smFolder := filepath.Join(v2, val.SchemeManagerID)
			// Check and create schememanager folder
			if err = common.AssertPathExists(smFolder); err != nil {
				if err := os.Mkdir(smFolder, os.ModePerm); err != nil {
					return errors.WrapPrefix(err, "Error creating directory", 0)
				}
			}

			buf, err := json.Marshal(val)
			if err != nil {
				return errors.WrapPrefix(err, "Error creating json", 0)
			}

			// Pretty format JSON
			prettyJson, err := PrettyString(string(buf))
			if err != nil {
				return errors.WrapPrefix(err, "Error pretty printing json", 0)
			}

			// Write to file
			bts := []byte(prettyJson)
			if err := os.WriteFile(filepath.Join(smFolder, val.CredentialTypeID+".jsonld"), bts, 0644); err != nil {
				return errors.WrapPrefix(err, "Failed to write description", 0)
			}
		}

		v3 := filepath.Join(dest, "v3")
		if err = common.AssertPathExists(v3); err != nil {
			if err := os.Mkdir(v3, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating JSON directory", 0)
			}
		}
		for _, val := range attributeTypes {
			smFolder := filepath.Join(v3, val.SchemeManagerID)
			// Check and create schememanager folder
			if err = common.AssertPathExists(smFolder); err != nil {
				if err := os.Mkdir(smFolder, os.ModePerm); err != nil {
					return errors.WrapPrefix(err, "Error creating directory", 0)
				}
			}

			buf, err := json.Marshal(val)
			if err != nil {
				return errors.WrapPrefix(err, "Error creating json", 0)
			}

			// Pretty format JSON
			prettyJson, err := PrettyString(string(buf))
			if err != nil {
				return errors.WrapPrefix(err, "Error pretty printing json", 0)
			}

			// Write to file
			bts := []byte(prettyJson)
			if err := os.WriteFile(filepath.Join(smFolder, val.CredentialTypeID+".jsonld"), bts, 0644); err != nil {
				return errors.WrapPrefix(err, "Failed to write description", 0)
			}

			issuerFolder := filepath.Join(smFolder, val.IssuerID)
			// Check and create issuer folder
			if err = common.AssertPathExists(issuerFolder); err != nil {
				if err := os.Mkdir(issuerFolder, os.ModePerm); err != nil {
					return errors.WrapPrefix(err, "Error creating directory", 0)
				}
			}

			buf, err = json.Marshal(val)
			if err != nil {
				return errors.WrapPrefix(err, "Error creating json", 0)
			}

			// Pretty format JSON
			prettyJson, err = PrettyString(string(buf))
			if err != nil {
				return errors.WrapPrefix(err, "Error pretty printing json", 0)
			}

			// Write to file
			bts = []byte(prettyJson)
			if err := os.WriteFile(filepath.Join(issuerFolder, val.CredentialTypeID+".jsonld"), bts, 0644); err != nil {
				return errors.WrapPrefix(err, "Failed to write description", 0)
			}
		}

		return nil
	},
}

func init() {
	schemeCmd.AddCommand(typesCmd)
}
