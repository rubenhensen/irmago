// Package irmaserver is a library that allows IRMA verifiers, issuers or attribute-based signature
// applications to perform IRMA sessions with irmaclient instances (i.e. the IRMA app). It exposes
// functions for handling IRMA sessions and a HTTP handler that handles the sessions with the
// irmaclient.
package irmaserver

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/servercore"
	"github.com/privacybydesign/irmago/server"
)

// Server is an irmaserver instance.
type Server struct {
	*servercore.Server
	handlers map[string]SessionHandler
}

// SessionHandler is a function that can handle a session result
// once an IRMA session has completed.
type SessionHandler func(*server.SessionResult)

// Default server instance
var s *Server

// Initialize the default server instance with the specified configuration using New().
func Initialize(conf *server.Configuration) (err error) {
	s, err = New(conf)
	return
}

// New creates a new Server instance with the specified configuration.
func New(conf *server.Configuration) (*Server, error) {
	s, err := servercore.New(conf)
	if err != nil {
		return nil, err
	}
	return &Server{
		Server:   s,
		handlers: make(map[string]SessionHandler),
	}, nil
}

// Stop the server.
func Stop() {
	s.Stop()
}
func (s *Server) Stop() {
	s.Server.Stop()
}

// StartSession starts an IRMA session, running the handler on completion, if specified.
// The session token (the second return parameter) can be used in GetSessionResult()
// and CancelSession().
// The request parameter can be an irma.RequestorRequest, or an irma.SessionRequest, or a
// ([]byte or string) JSON representation of one of those (for more details, see server.ParseSessionRequest().)
func StartSession(request interface{}, handler SessionHandler) (*irma.Qr, string, error) {
	return s.StartSession(request, handler)
}
func (s *Server) StartSession(request interface{}, handler SessionHandler) (*irma.Qr, string, error) {
	qr, token, err := s.Server.StartSession(request)
	if err != nil {
		return nil, "", err
	}
	if handler != nil {
		s.handlers[token] = handler
	}
	return qr, token, nil
}

// GetSessionResult retrieves the result of the specified IRMA session.
func GetSessionResult(token string) *server.SessionResult {
	return s.GetSessionResult(token)
}
func (s *Server) GetSessionResult(token string) *server.SessionResult {
	return s.Server.GetSessionResult(token)
}

// GetRequest retrieves the request submitted by the requestor that started the specified IRMA session.
func GetRequest(token string) irma.RequestorRequest {
	return s.GetRequest(token)
}
func (s *Server) GetRequest(token string) irma.RequestorRequest {
	return s.Server.GetRequest(token)
}

// CancelSession cancels the specified IRMA session.
func CancelSession(token string) error {
	return s.CancelSession(token)
}
func (s *Server) CancelSession(token string) error {
	return s.Server.CancelSession(token)
}

// SubscribeServerSentEvents subscribes the HTTP client to server sent events on status updates
// of the specified IRMA session.
func SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token string, requestor bool) error {
	return s.SubscribeServerSentEvents(w, r, token, requestor)
}
func (s *Server) SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token string, requestor bool) error {
	return s.Server.SubscribeServerSentEvents(w, r, token, requestor)
}

// HandlerFunc returns a http.HandlerFunc that handles the IRMA protocol
// with IRMA apps.
//
// Example usage:
//   http.HandleFunc("/irma/", irmaserver.HandlerFunc())
//
// The IRMA app can then perform IRMA sessions at https://example.com/irma.
func HandlerFunc() http.HandlerFunc {
	return s.HandlerFunc()
}

func (s *Server) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var message []byte
		var err error
		if r.Method == http.MethodPost {
			if message, err = ioutil.ReadAll(r.Body); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		token, noun, err := servercore.ParsePath(r.URL.Path)
		if err == nil && noun == "statusevents" { // if err != nil we let it be handled by HandleProtocolMessage below
			if err = s.SubscribeServerSentEvents(w, r, token, false); err != nil {
				server.WriteResponse(w, nil, &irma.RemoteError{
					Status:      server.ErrorUnsupported.Status,
					ErrorName:   string(server.ErrorUnsupported.Type),
					Description: server.ErrorUnsupported.Description,
				})
			}
			return
		}

		status, response, result := s.HandleProtocolMessage(r.URL.Path, r.Method, r.Header, message)
		w.WriteHeader(status)
		_, err = w.Write(response)
		if err != nil {
			_ = server.LogError(errors.WrapPrefix(err, "http.ResponseWriter.Write() returned error", 0))
		}
		if result != nil && result.Status.Finished() {
			if handler := s.handlers[result.Token]; handler != nil {
				go handler(result)
			}
		}
	}
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


func (s *Server) VCHandler(endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var status int
		var message []byte
		var err error

		// Only GET allowed
		if r.Method == http.MethodPost {
			if message, err = ioutil.ReadAll(r.Body); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		path := r.URL.Path

		if len(path) > 0 { // Remove any starting and trailing slash
			if path[0] == '/' {
				path = path[1:]
			}
			if path[len(path)-1] == '/' {
				path = path[:len(path)-1]
			}
		}

		matches := strings.Split(path, "/")

		if len(matches) != 4 {
			_ = server.LogWarning(errors.Errorf("Invalid URL: %s", path))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		switch endpoint {
		case "type":
			status, message = server.JsonResponse(s.handleTypeRequest(matches))
		case "issuer":
			status, message = server.JsonResponse(s.handleIssuerRequest(matches))
		case "schema":
			stringMessage, _ := s.handleSchemaRequest(matches)
			message = []byte(stringMessage)
			status = http.StatusOK
		}

		w.WriteHeader(status)
		_, err = w.Write(message)
		if err != nil {
			_ = server.LogError(errors.WrapPrefix(err, "http.ResponseWriter.Write() returned error", 0))
		}
	}
}

// Types required to compute the credentialSchema

type AnyOf struct {
	Req []string `json:"required"`
}

type Required struct {
	Req []string `json:"required"`
}

type Attribute struct {
	Ref string `json:"$ref"`
}

type CredType struct {
	AdditionalProperties bool `json:"additionalProperties"`
	AnyOf	[]AnyOf `json:"anyOf"`
	Description string `json:"description"`
	Properties map[string]Attribute `json:"properties"`
	Type string `json:"type"`
}

type Type string

type En struct {
	Type `json:"type"`
}

type Nl struct {
	Type `json:"type"`
}

type RawValue struct {
	Type `json:"type"`
}

type Properties struct {
	En `json:"en"`
	Nl`json:"nl"`
	RawValue `json:"rawValue"`
}

type TranslatedStringSchema struct {
	Properties `json:"properties"`
	Required []string `json:"required"`
	Type     string   `json:"type"`
}

type DefaultSchema struct {
	Type     string   	`json:"type"`
	Items    []Item		`json:"items"`
}

type Item  struct {
AdditionalProperties bool `json:"additionalProperties"`
Properties struct {
CredType struct {
Ref string `json:"$ref"`
} `json:"credType"`
} `json:"properties"`
Required []string `json:"required"`
}

type Definitions          struct {
CredType `json:"credType"`
TranslatedStringSchema `json:"translatedString"`
}

var translatedString = TranslatedStringSchema {
	Required: []string{"rawValue", "en", "nl"},
	Properties: Properties{ En{  Type:"string" }, Nl{ Type:"string"},  RawValue{Type:"string"}},
	Type: "object",
}

func (s *Server) handleSchemaRequest(schemaRequest []string) (string, *irma.RemoteError) {
	var schema DefaultSchema
	var credType CredType
	var definitions Definitions
	var items []Item
	var item Item

	conf := s.GetConfig()

	credID := irma.NewCredentialTypeIdentifier(schemaRequest[1] + "." + schemaRequest[2] + "." + schemaRequest[3])
	credentialType := conf.IrmaConfiguration.CredentialTypes[credID]
	credType.Properties = map[string]Attribute{}

	for _, attr := range credentialType.AttributeTypes {
		var jsAttr Attribute
		var anyOf AnyOf

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
		panic (err)
	}

	outString := strings.Replace(string(out), "credType", credentialType.ID, -1)
	outString = jsonPrettyPrint(outString)

	outString = strings.Replace(string(defaultSchema), "$subject", outString, -1)

	definitions2 := strings.Replace(string(definitionsByte), "credType", credentialType.ID, -1)
	definitions2 = jsonPrettyPrint(definitions2)
	definitions2 = strings.TrimSuffix(definitions2, "}" )
	definitions2 = strings.TrimPrefix(definitions2, "{" )

	outString = strings.Replace(outString, "$definition", jsonPrettyPrint(string(definitions2)), -1)

	return outString, nil
}

func (s *Server) handleTypeRequest(typeRequest []string) (irma.VCType, *irma.RemoteError) {
	conf := s.GetConfig()

	credID := irma.NewCredentialTypeIdentifier(typeRequest[1] + "." + typeRequest[2] + "." + typeRequest[3])
	credentialType := conf.IrmaConfiguration.CredentialTypes[credID]

	vcType := irma.VCType{}

	LDContext := make(map[string]string)
	LDContext["irma"] = "http://irma.app/irma-schema/"
	LDContext["schema"] = "http://schema.org/"

	vcType = make(map[string]interface{})
	vcType["@context"] = LDContext

	for _, attr := range credentialType.AttributeTypes {
		vcAttType := irma.VCAttributeType{}
		if len(attr.DataType) != 0 {
			vcAttType.Type = "schema:" + attr.DataType
		} else {
			// If no type is specified, use schema:Text as default
			vcAttType.Type = "schema:Text"
		}
		vcAttType.Comment = attr.Description["en"]
		vcAttType.ID = "irma:" + attr.GetAttributeTypeIdentifier().String()
		vcType["irma:"+attr.ID] = vcAttType
	}

	return vcType, nil
}

func (s *Server) handleIssuerRequest(typeRequest []string) (irma.VCType, *irma.RemoteError) {
	conf := s.GetConfig()

	issuer := irma.NewIssuerIdentifier(typeRequest[1] + "." + typeRequest[2])
	issuerType := conf.IrmaConfiguration.Issuers[issuer]
	counter, _ := strconv.Atoi(typeRequest[3])
	pk, _ := conf.IrmaConfiguration.PublicKey(issuer, counter)

	vcIssuer := make(map[string]interface{})
	vcIssuer["email"] = issuerType.ContactEMail
	vcIssuer["pk"] = pk

	return vcIssuer, nil
}
