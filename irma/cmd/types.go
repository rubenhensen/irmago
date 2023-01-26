package cmd

import (
	"fmt"
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
			if err := os.Mkdir(dest, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating JSON directory", 0)
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
		for key, val := range attributeTypes {
			smFolder := filepath.Join(dest, val.SchemeManagerID)
			// Check and create schememanager folder
			if err = common.AssertPathExists(smFolder); err != nil {
				if err := os.Mkdir(smFolder, os.ModePerm); err != nil {
					return errors.WrapPrefix(err, "Error creating directory", 0)
				}
			}

			issuerFolder := filepath.Join(dest, val.IssuerID)
			// Check and create issuer folder
			if err = common.AssertPathExists(issuerFolder); err != nil {
				if err := os.Mkdir(issuerFolder, os.ModePerm); err != nil {
					return errors.WrapPrefix(err, "Error creating directory", 0)
				}
			}

			// issuerFolder := filepath.Join(dest, val.IssuerID)
			// // Check and create issuer folder
			// if err = common.AssertPathExists(dest); err != nil {
			// 	if err := os.Mkdir(dest, os.ModePerm); err != nil {
			// 		return errors.WrapPrefix(err, "Error creating directory", 0)
			// 	}
			// }
			fmt.Printf("attr. key: %v , val: %v\n", key, val)

			// ID:					"profile"
			// Optional:			""
			// Name:				github.com/privacybydesign/irmago.TranslatedString ["en": "Profile", "nl": "Profiel", ]
			// Description:			github.com/privacybydesign/irmago.TranslatedString ["en": "Education profile", "nl": "Opleidingsprofiel", ]
			// RandomBlind:			false
			// Index:				7
			// DisplayIndex:		*int nil
			// DisplayHint:			""
			// RevocationAttribute:	false
			// CredentialTypeID:	"demodiploma"
			// IssuerID:			"DemoDuo"
			// SchemeManagerID:		"irma-demo"

		}

		// func (s *Server) handleTypeRequest(typeRequest []string) (irma.VCType, *irma.RemoteError) {
		// 	conf := s.GetConfig()

		// 	credID := irma.NewCredentialTypeIdentifier(typeRequest[1] + "." + typeRequest[2] + "." + typeRequest[3])
		// 	credentialType := conf.IrmaConfiguration.CredentialTypes[credID]

		// 	vcType := irma.VCType{}

		// 	LDContext := make(map[string]string)
		// 	LDContext["irma"] = "http://irma.app/irma-schema/"
		// 	LDContext["schema"] = "http://schema.org/"

		// 	vcType = make(map[string]interface{})
		// 	vcType["@context"] = LDContext

		// 	for _, attr := range credentialType.AttributeTypes {
		// 		vcAttType := irma.VCAttributeType{}
		// 		if len(attr.DataType) != 0 {
		// 			vcAttType.Type = "schema:" + attr.DataType
		// 		} else {
		// 			// If no type is specified, use schema:Text as default
		// 			vcAttType.Type = "schema:Text"
		// 		}
		// 		vcAttType.Comment = attr.Description["en"]
		// 		vcAttType.ID = "irma:" + attr.GetAttributeTypeIdentifier().String()
		// 		vcType["irma:"+attr.ID] = vcAttType
		// 	}

		// 	return vcType, nil
		// }

		// if jsonPkg == "" {
		// 	request, irmaconfig, err = configureSession(cmd)
		// 	if err != nil {
		// 		die("", err)
		// 	}
		// 	if serverURL != "" {
		// 		authMethod, _ := flags.GetString("authmethod")
		// 		key, _ := flags.GetString("key")
		// 		name, _ := flags.GetString("name")
		// 		pkg, err = postRequest(serverURL, request, name, authMethod, key)
		// 		if err != nil {
		// 			die("Session could not be started", err)
		// 		}
		// 	}
		// } else {
		// 	pkg = &server.SessionPackage{}
		// 	err = json.Unmarshal([]byte(jsonPkg), pkg)
		// 	if err != nil {
		// 		die("Failed to parse session package", err)
		// 	}
		// }

		// wd, err := os.Getwd()
		// if err != nil {
		// 	die("Failed to get wd", err)
		// }

		// if url != defaulturl && src != wd {
		// 	die("Failed to read configuration", errors.New("--url can't be combined with --src"))
		// }

		// if err = common.AssertPathExists(src); err != nil {
		// 	return errors.WrapPrefix(err, "Source directory does not exist", 0)
		// }

		// if err = common.AssertPathExists(dest); err != nil {
		// 	if err := os.Mkdir(dest, os.ModePerm); err != nil {
		// 		return errors.WrapPrefix(err, "Error creating destination directory", 0)
		// 	}
		// }

		// if err := createTypeScheme(url); err != nil {
		// 	die("Failed to convert scheme", err)
		// }

		return nil
	},
}

func init() {
	schemeCmd.AddCommand(typesCmd)
	// wd, err := os.Getwd()
	// if err != nil {
	// 	die("Failed to get wd", err)
	// }

	// flags := typesCmd.Flags()
	// flags.StringP("url", "u", "https://privacybydesign.foundation/schememanager/pbdf", "External URL to scheme manager.")
	// flags.StringP("src", "s", wd, "Filepath to the scheme manager where all types should be exported from. Defaults to <working-directory>.")
	// flags.StringP("dest", "d", filepath.Join(wd, "typeScheme"), "Filepath to destination folder types should be exported to. Defaults to <working-directory>/typeScheme")
}

// func createTypeScheme() error {

// if pkg == nil {
// 	port, _ := flags.GetInt("port")
// 	privatekeysPath, _ := flags.GetString("privkeys")
// 	verbosity, _ := cmd.Flags().GetCount("verbose")
// 	result, err = libraryRequest(request, irmaconfig, url, port, privatekeysPath, noqr, verbosity, pairing)
// } else {
// 	result, err = serverRequest(pkg, noqr, pairing)
// }
// if err != nil {
// 	die("Session failed", err)
// }

// printSessionResult(result)

// Done!
// if httpServer != nil {
// 	_ = httpServer.Close()
// }

// }

// func RequestorServerConfiguration() *requestorserver.Configuration {
// 	irmaServerConf := myIrmaServerConfiguration()
// 	irmaServerConf.URL = requestorServerURL + "/irma"
// 	return &requestorserver.Configuration{
// 		Configuration:                  irmaServerConf,
// 		DisableRequestorAuthentication: true,
// 		ListenAddress:                  "localhost",
// 		Port:                           requestorServerPort,
// 		MaxRequestAge:                  3,
// 		Permissions: requestorserver.Permissions{
// 			Disclosing: []string{"*"},
// 			Signing:    []string{"*"},
// 			Issuing:    []string{"*"},
// 		},
// 	}
// }

// func myIrmaServerConfiguration() *server.Configuration {
// 	return &server.Configuration{
// 		URL:                   fmt.Sprintf("http://localhost:%d", irmaServerPort),
// 		Logger:                logger,
// 		DisableSchemesUpdate:  false,
// 		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
// 		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
// 		RevocationSettings: irma.RevocationSettings{
// 			revocationTestCred:  {RevocationServerURL: revocationServerURL, SSE: true},
// 			revKeyshareTestCred: {RevocationServerURL: revocationServerURL},
// 		},
// 		JwtPrivateKeyFile: jwtPrivkeyPath,
// 		StaticSessions: map[string]interface{}{
// 			"staticsession": irma.ServiceProviderRequest{
// 				RequestorBaseRequest: irma.RequestorBaseRequest{
// 					CallbackURL: staticSessionServerURL,
// 				},
// 				Request: &irma.DisclosureRequest{
// 					BaseRequest: irma.BaseRequest{LDContext: irma.LDContextDisclosureRequest},
// 					Disclose: irma.AttributeConDisCon{
// 						{{irma.NewAttributeRequest("irma-demo.RU.studentCard.level")}},
// 					},
// 				},
// 			},
// 		},
// 	}
// }
