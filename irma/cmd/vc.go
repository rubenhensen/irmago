package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	irma "github.com/privacybydesign/irmago"
	"github.com/spf13/cobra"
)

var vcCmd = &cobra.Command{
	Use:   "vc [file]",
	Short: "Verifies verifiable credentials",
	Long:  `This endpoint is used to run the vc-test-suite from w3c`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		vc := fileToVC(args[0])
		err := vc.Validate()
		if err != nil {
			die("Failed to validate vc", err)
		}
		fmt.Println(fileToVC(args[0]))
	},
}

func init() {
	RootCmd.AddCommand(vcCmd)
}

func fileToVC(path string) irma.VerifiableCredential {
	// Open our jsonFile
	jsonFile, err := os.Open(path)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	vc := irma.VerifiableCredential{}

	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'users' which we defined above
	if err = json.Unmarshal(byteValue, &vc); err != nil {
		die("", err)
	}

	return vc
}
