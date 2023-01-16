package cmd

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"

	xj "github.com/basgys/goxml2json"
)

// signCmd represents the sign command
var convertCmd = &cobra.Command{
	Use:   "convert [<src>] [<dest>]",
	Short: "Convert a scheme directory to JSON(LD)",
	Long: `Convert a scheme directory to JSON(LD). Both arguments are optional; the working directory is the default. Recursively converts every XML file to JSON(LD) files. Additionally moves the public and private keys, and makes seperate files for all the types.

Careful: this command could fail and invalidate or destroy your scheme directory! Use this only if you can restore it from git or backups.`,
	Args: cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate arguments
		var err, err_src, err_dest error
		var wd string
		var srcpath string
		var destpath string

		wd, err = os.Getwd()
		if err != nil {
			return errors.WrapPrefix(err, "Error getting working directory", 0)
		}

		switch len(args) {
		case 0:
			srcpath = wd
			destpath = filepath.Join(wd, "json")
			if err := os.Mkdir(destpath, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating JSON directory", 0)
			}
		case 1:
			srcpath, err = filepath.Abs(args[0])
			destpath = filepath.Join(wd, "json")
			if err := os.Mkdir(destpath, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating JSON directory", 0)
			}
		case 2:
			srcpath, err_src = filepath.Abs(args[0])
			destpath, err_dest = filepath.Abs(args[1])
		}
		if err_src != nil {
			return errors.WrapPrefix(err, "Invalid src path", 0)
		}

		if err_dest != nil {
			return errors.WrapPrefix(err, "Invalid dest path", 0)
		}

		if err = common.AssertPathExists(srcpath); err != nil {
			return err
		}

		if err = common.AssertPathExists(destpath); err != nil {
			if err := os.Mkdir(destpath, os.ModePerm); err != nil {
				return errors.WrapPrefix(err, "Error creating directory", 0)
			}
		}

		if err := convertScheme(srcpath, destpath); err != nil {
			die("Failed to convert scheme", err)
		}

		return nil
	},
}

func init() {
	schemeCmd.AddCommand(convertCmd)
}

func convertScheme(src, dest string) error {
	var demo bool
	demo, err := isDemo(src)
	if err != nil {
		return errors.WrapPrefix(err, "Error reading files in src directory", 0)
	}

	// Get all file names root dir
	files, err := os.ReadDir(src)
	if err != nil {
		return errors.WrapPrefix(err, "Error reading files in src directory", 0)
	}

	for _, file := range files {
		if file.IsDir() {
			convertIssuer(filepath.Join(src, file.Name()), filepath.Join(dest, file.Name()), demo)
		}

		if file.Name() == "description.xml" {
			convertSchemeManager(src, dest, demo)
			continue
		}

		copyFile(filepath.Join(src, file.Name()), filepath.Join(dest, file.Name()))
	}

	return nil
}

func isDemo(src string) (bool, error) {
	xmlFilePath := filepath.Join(src, "description.xml")
	xmlFile, err := os.ReadFile(xmlFilePath)
	if err != nil {
		return false, errors.WrapPrefix(err, "Error opening file", 0)
	}
	re, err := regexp.Compile(`<Demo>true</Demo>`)
	if err != nil {
		return false, errors.WrapPrefix(err, "Error creating regex", 0)
	}
	result := re.Find(xmlFile)
	if result == nil {
		return false, nil
	} else {
		return true, nil
	}
}

func issuerKeys(src, dest, foldername string, demo bool) ([]*xj.Node, error) {
	var ks []*xj.Node
	var err error
	// Create issuer folder
	if err = common.AssertPathExists(dest); err != nil {
		if err := os.Mkdir(dest, os.ModePerm); err != nil {
			return ks, errors.WrapPrefix(err, "Error creating directory", 0)
		}
	}

	// Get all pks
	folderPath := filepath.Join(src, foldername)
	files, err := os.ReadDir(folderPath)
	if err != nil {
		return ks, errors.WrapPrefix(err, "Error reading files in src directory", 0)
	}

	for _, file := range files {
		// Convert to json
		path := filepath.Join(folderPath, file.Name())
		xmlFile, err := os.Open(path)
		if err != nil {
			return ks, errors.WrapPrefix(err, "Error converting to json", 0)
		}

		// Decode XML document
		root := &xj.Node{}
		err = xj.NewDecoder(xmlFile).Decode(root)
		if err != nil {
			return nil, err
		}

		ks = append(ks, root)

	}
	return ks, nil
}

func convertIssuer(src, dest string, demo bool) error {
	var err error

	// Get all file names root dir
	files, err := os.ReadDir(src)
	if err != nil {
		return errors.WrapPrefix(err, "Error reading files in src directory", 0)
	}
	var skeys, pkeys []*xj.Node
	for _, file := range files {
		if file.IsDir() && file.Name() == "PublicKeys" {
			pkeys, err = issuerKeys(src, dest, "PublicKeys", demo)
			if err != nil {
				return errors.WrapPrefix(err, "Error reading public keys", 0)
			}
			continue
		}

		if file.IsDir() && file.Name() == "PrivateKeys" {
			skeys, err = issuerKeys(src, dest, "PrivateKeys", demo)
			if err != nil {
				return errors.WrapPrefix(err, "Error reading private keys", 0)
			}
			continue
		}
		if file.Name() != "description.xml" {
			copyFile(filepath.Join(src, file.Name()), filepath.Join(dest, file.Name()))
		}
	}

	// Convert desription.xml and embed pk/sk
	convertIssuerDesc(src, dest, demo, skeys, pkeys)

	return nil
}

func convertIssuerDesc(src, dest string, demo bool, skeys, pkeys []*xj.Node) error {
	// Get description.xml
	xmlFilePath := filepath.Join(src, "description.xml")
	xmlFile, err := os.Open(xmlFilePath)
	if err != nil {
		return errors.WrapPrefix(err, "Error opening file", 0)
	}

	// Decode XML document
	root := &xj.Node{}
	err = xj.NewDecoder(xmlFile).Decode(root)
	if err != nil {
		return err
	}

	// Add pk and sk
	AddAttr(root, "Issuer", "PublicKeys", "")
	if demo {
		AddAttr(root, "Issuer", "PrivateKeys", "")
	}

	for i, v := range pkeys {
		AddNode(root, "PublicKeys", strconv.Itoa(i), v)
	}

	for i, v := range skeys {
		AddNode(root, "PrivateKeys", strconv.Itoa(i), v)
	}

	// Then encode it in JSON
	buf := new(bytes.Buffer)
	e := xj.NewEncoder(buf)
	err = e.Encode(root)
	if err != nil {
		return err
	}

	// Pretty format JSON
	prettyJson, err := PrettyString(buf.String())
	if err != nil {
		return errors.WrapPrefix(err, "Error pretty printing json", 0)
	}

	// Write to file
	bts := []byte(prettyJson)
	if err := os.WriteFile(filepath.Join(dest, "description.jsonld"), bts, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write description", 0)
	}

	return nil
}

func convertSchemeManager(src, dest string, demo bool) error {
	// Get pk
	pkFilePath := filepath.Join(src, "pk.pem")
	pkFile, err := os.ReadFile(pkFilePath)
	if err != nil {
		return errors.WrapPrefix(err, "Error opening file", 0)
	}
	pkFileStr := string(pkFile)
	re, err := regexp.Compile(`\n`)
	if err != nil {
		return errors.WrapPrefix(err, "Error regex", 0)
	}
	pkFileStr = re.ReplaceAllString(pkFileStr, "")

	// Get sk
	var skFileStr string
	if demo {
		skFilePath := filepath.Join(src, "sk.pem")
		skFile, err := os.ReadFile(skFilePath)
		skFileStr = string(skFile)
		if err != nil {
			return errors.WrapPrefix(err, "Error opening file", 0)
		}
		skFileStr = re.ReplaceAllString(skFileStr, "")
	}

	// Get description.xml
	xmlFilePath := filepath.Join(src, "description.xml")
	xmlFile, err := os.Open(xmlFilePath)
	if err != nil {
		return errors.WrapPrefix(err, "Error opening file", 0)
	}

	// Decode XML document
	root := &xj.Node{}
	err = xj.NewDecoder(xmlFile).Decode(root)
	if err != nil {
		return err
	}

	// Add pk and sk
	AddAttr(root, "SchemeManager", "PublicKey", pkFileStr)
	if demo {
		AddAttr(root, "SchemeManager", "PrivateKey", skFileStr)
	}

	// Then encode it in JSON
	buf := new(bytes.Buffer)
	e := xj.NewEncoder(buf)
	err = e.Encode(root)
	if err != nil {
		return err
	}

	// Pretty format JSON
	prettyJson, err := PrettyString(buf.String())
	if err != nil {
		return errors.WrapPrefix(err, "Error pretty printing json", 0)
	}

	// Write to file
	bts := []byte(prettyJson)
	if err := os.WriteFile(filepath.Join(dest, "description.jsonld"), bts, 0644); err != nil {
		return errors.WrapPrefix(err, "Failed to write description", 0)
	}

	return nil
}

func AddAttr(n *xj.Node, searchKey, key, value string) {
	for k, v := range n.Children {
		if k == searchKey {
			v[0].AddChild(key, &xj.Node{Data: value})
		} else if len(v) != 0 {
			for _, v2 := range v {
				AddAttr(v2, searchKey, key, value)
			}
		} else {
			panic("could not find key")
		}
	}
}

func AddNode(n *xj.Node, searchKey, key string, node *xj.Node) {
	for k, v := range n.Children {
		if k == searchKey {
			v[0].AddChild(key, node)
		} else if len(v) != 0 {
			for _, v2 := range v {
				AddNode(v2, searchKey, key, node)
			}
		} else {
			panic("could not find key")
		}
	}
}

func PrettyString(str string) (string, error) {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(str), "", "    "); err != nil {
		return "", err
	}
	return prettyJSON.String(), nil
}

// from https://github.com/mactsouk/opensource.com/blob/master/cp1.go
func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

type SchemeManagerJSON struct {
	SchemeManager struct {
		Description struct {
			En string `json:"en"`
			Nl string `json:"nl"`
		} `json:"Description"`
		TimestampServer string `json:"TimestampServer"`
		Contact         string `json:"Contact"`
		Version         string `json:"-version"`
		ID              string `json:"Id"`
		URL             string `json:"Url"`
		Demo            string `json:"Demo,omitempty"`
		PublicKey       string `json:"PublicKey"`
		PrivateKey      string `json:"PrivateKey,omitempty"`
		Name            struct {
			En string `json:"en"`
			Nl string `json:"nl"`
		} `json:"Name"`
	} `json:"SchemeManager"`
}

type SchemeManagerXML struct {
	XMLName xml.Name `xml:"SchemeManager"`
	Text    string   `xml:",chardata"`
	Version string   `xml:"version,attr"`
	ID      string   `xml:"Id"`
	URL     string   `xml:"Url"`
	Demo    string   `xml:"Demo"`
	Name    struct {
		Text string `xml:",chardata"`
		En   string `xml:"en"`
		Nl   string `xml:"nl"`
	} `xml:"Name"`
	Description struct {
		Text string `xml:",chardata"`
		En   string `xml:"en"`
		Nl   string `xml:"nl"`
	} `xml:"Description"`
	TimestampServer string `xml:"TimestampServer"`
	Contact         string `xml:"Contact"`
}

type IssuerPublicKeyXML struct {
	XMLName    xml.Name `xml:"IssuerPublicKey"`
	Text       string   `xml:",chardata"`
	Xmlns      string   `xml:"xmlns,attr"`
	Counter    string   `xml:"Counter"`
	ExpiryDate string   `xml:"ExpiryDate"`
	Elements   struct {
		Text  string `xml:",chardata"`
		N     string `xml:"n"`
		Z     string `xml:"Z"`
		S     string `xml:"S"`
		Bases struct {
			Text  string `xml:",chardata"`
			Num   string `xml:"num,attr"`
			Base0 string `xml:"Base_0"`
			Base1 string `xml:"Base_1"`
			Base2 string `xml:"Base_2"`
			Base3 string `xml:"Base_3"`
			Base4 string `xml:"Base_4"`
			Base5 string `xml:"Base_5"`
			Base6 string `xml:"Base_6"`
			Base7 string `xml:"Base_7"`
		} `xml:"Bases"`
	} `xml:"Elements"`
	Features struct {
		Text  string `xml:",chardata"`
		Epoch struct {
			Text   string `xml:",chardata"`
			Length string `xml:"length,attr"`
		} `xml:"Epoch"`
	} `xml:"Features"`
}

type IssuerPublicKeyJSON struct {
	IssuerPublicKey struct {
		Xmlns      string `json:"-xmlns"`
		Counter    string `json:"Counter"`
		ExpiryDate string `json:"ExpiryDate"`
		Elements   struct {
			S     string `json:"S"`
			G     string `json:"G"`
			H     string `json:"H"`
			Bases struct {
				Num    string `json:"-num"`
				Base0  string `json:"Base_0"`
				Base1  string `json:"Base_1"`
				Base2  string `json:"Base_2"`
				Base3  string `json:"Base_3"`
				Base4  string `json:"Base_4"`
				Base5  string `json:"Base_5"`
				Base6  string `json:"Base_6"`
				Base7  string `json:"Base_7"`
				Base8  string `json:"Base_8"`
				Base9  string `json:"Base_9"`
				Base10 string `json:"Base_10"`
				Base11 string `json:"Base_11"`
			} `json:"Bases"`
			N string `json:"n"`
			Z string `json:"Z"`
		} `json:"Elements"`
		Features struct {
			Epoch struct {
				Length string `json:"-length"`
			} `json:"Epoch"`
		} `json:"Features"`
		ECDSA string `json:"ECDSA"`
	} `json:"IssuerPublicKey"`
}

type IssuerPrivateKeyJSON struct {
	IssuerPrivateKey struct {
		Xmlns      string `json:"-xmlns"`
		Counter    string `json:"Counter"`
		ExpiryDate string `json:"ExpiryDate"`
		Elements   struct {
			P      string `json:"p"`
			Q      string `json:"q"`
			PPrime string `json:"pPrime"`
			QPrime string `json:"qPrime"`
		} `json:"Elements"`
		ECDSA string `json:"ECDSA"`
	} `json:"IssuerPrivateKey"`
}
