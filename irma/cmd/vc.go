package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	ariesvc "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
)

var vcCmd = &cobra.Command{
	Use:   "vc [file]",
	Short: "Verifies verifiable credentials",
	Long:  `This endpoint is used to run the vc-test-suite from w3c`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		vc, err := fileToCredential(args[0])
		if err != nil {

			die("", err)
		}
		b, err := json.Marshal(vc)
		if err != nil {
			die("", err)
		}
		fmt.Print(string(b))
	},
}

func init() {
	RootCmd.AddCommand(vcCmd)
}

func fileToCredential(path string) (*ariesvc.Credential, error) {
	// Open our jsonFile
	jsonFile, err := os.ReadFile(path)
	// if we os.Open returns an error then handle it
	if err != nil {
		die("", err)
	}

	// TODO: Check if there is a more efficient way
	client := &http.Client{}
	nl := ld.NewDefaultDocumentLoader(client)

	vcParsed, err := ariesvc.ParseCredential(
		jsonFile,
		ariesvc.WithStrictValidation(),
		ariesvc.WithDisabledProofCheck(),
		// ariesvc.WithEmbeddedSignatureSuites(), // Could be used to add a idemix proof checker to ariesvc
		ariesvc.WithJSONLDDocumentLoader(nl),
		ariesvc.WithNoCustomSchemaCheck()) // makes sure no http request for schema

	return vcParsed, err
}
