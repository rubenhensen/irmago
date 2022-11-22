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

var vpCmd = &cobra.Command{
	Use:   "vp [file]",
	Short: "Verifies verifiable presentations",
	Long:  `This endpoint is used to run the vc-test-suite from w3c`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		vc, err := fileToPresentation(args[0])
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
	RootCmd.AddCommand(vpCmd)
}

func fileToPresentation(path string) (*ariesvc.Presentation, error) {
	// Open our jsonFile
	jsonFile, err := os.ReadFile(path)
	// if we os.Open returns an error then handle it
	if err != nil {
		die("", err)
	}
	// TODO: Check if there is a more efficient way
	client := &http.Client{}
	nl := ld.NewDefaultDocumentLoader(client)
	vcParsed, err := ariesvc.ParsePresentation(jsonFile,
		ariesvc.WithPresDisabledProofCheck(),
		ariesvc.WithPresJSONLDDocumentLoader(nl))

	return vcParsed, err
}
