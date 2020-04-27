package irmaclient

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
)

// This file contains the logic and state of performing IRMA sessions, communicates
// with IRMA API servers, and uses the calling Client to construct messages and replies
// in the IRMA protocol.

// PermissionHandler is a callback for providing permission for an IRMA session
// and specifying the attributes to be disclosed.
type PermissionHandler func(proceed bool, choice *irma.DisclosureChoice)

// PinHandler is used to provide the user's PIN code.
type PinHandler func(proceed bool, pin string)

// A Handler contains callbacks for communication to the user.
type Handler interface {
	StatusUpdate(action irma.Action, status irma.Status)
	Success(result string)
	Cancelled()
	Failure(err *irma.SessionError)
	UnsatisfiableRequest(request irma.SessionRequest,
		ServerName irma.TranslatedString,
		missing MissingAttributes)

	KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int)
	KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier)
	KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier)
	KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier)

	RequestIssuancePermission(request *irma.IssuanceRequest,
		candidates [][][]*irma.AttributeIdentifier,
		ServerName irma.TranslatedString,
		callback PermissionHandler)
	RequestVerificationPermission(request *irma.DisclosureRequest,
		candidates [][][]*irma.AttributeIdentifier,
		ServerName irma.TranslatedString,
		callback PermissionHandler)
	RequestSignaturePermission(request *irma.SignatureRequest,
		candidates [][][]*irma.AttributeIdentifier,
		ServerName irma.TranslatedString,
		callback PermissionHandler)
	RequestSchemeManagerPermission(manager *irma.SchemeManager,
		callback func(proceed bool))

	RequestPin(remainingAttempts int, callback PinHandler)
}

// SessionDismisser can dismiss the current IRMA session.
type SessionDismisser interface {
	Dismiss()
}

type session struct {
	Action     irma.Action
	Handler    Handler
	Version    *irma.ProtocolVersion
	ServerName irma.TranslatedString

	choice      *irma.DisclosureChoice
	attrIndices irma.DisclosedAttributeIndices
	client      *Client
	request     irma.SessionRequest
	done        bool

	// State for issuance sessions
	issuerProofNonce *big.Int
	builders         gabi.ProofBuilderList

	// State for signature sessions
	timestamp *atum.Timestamp

	// These are empty on manual sessions
	Hostname  string
	ServerURL string
	transport *irma.HTTPTransport

	// Identify if session from external system
	extern 	  bool
}

// We implement the handler for the keyshare protocol
var _ keyshareSessionHandler = (*session)(nil)

// Supported protocol versions. Minor version numbers should be sorted.
var supportedVersions = map[int][]int{
	2: {
		4, // old protocol with legacy session requests
		5, // introduces condiscon feature
	},
}
var minVersion = &irma.ProtocolVersion{Major: 2, Minor: supportedVersions[2][0]}
var maxVersion = &irma.ProtocolVersion{Major: 2, Minor: supportedVersions[2][len(supportedVersions[2])-1]}

// Session constructors

// NewSession starts a new IRMA session, given (along with a handler to pass feedback to) a session request.
// When the request is not suitable to start an IRMA session from, it calls the Failure method of the specified Handler.
func (client *Client) NewSession(sessionrequest string, handler Handler) SessionDismisser {
	bts := []byte(sessionrequest)

	qr := &irma.Qr{}
	if err := irma.UnmarshalValidate(bts, qr); err == nil {
		return client.newQrSession(qr, handler, irma.IssueVC)
	}

	// Example: {"url":"http://192.168.2.100:8088/irma/f6JOn5NZqheTspDFISzW","action":"disclosing", "system":"sovrin"}
	qrSovrin := &irma.QrSovrin{}
	if err := irma.UnmarshalValidate(bts, qrSovrin); err == nil {
		qr.Type = qrSovrin.Type
		qr.URL = qrSovrin.URL
		return client.newQrSession(qr, handler, true)
	}

	schemeRequest := &irma.SchemeManagerRequest{}
	if err := irma.UnmarshalValidate(bts, schemeRequest); err == nil {
		return client.newSchemeSession(schemeRequest, handler)
	}

	sigRequest := &irma.SignatureRequest{}
	if err := irma.UnmarshalValidate(bts, sigRequest); err == nil {
		return client.newManualSession(sigRequest, handler, irma.ActionSigning)
	}

	disclosureRequest := &irma.DisclosureRequest{}
	if err := irma.UnmarshalValidate(bts, disclosureRequest); err == nil {
		return client.newManualSession(disclosureRequest, handler, irma.ActionDisclosing)
	}

	handler.Failure(&irma.SessionError{Err: errors.New("Session request could not be parsed"), Info: sessionrequest})
	return nil
}

// newManualSession starts a manual session, given a signature request in JSON and a handler to pass messages to
func (client *Client) newManualSession(request irma.SessionRequest, handler Handler, action irma.Action) SessionDismisser {
	session := &session{
		Action:  action,
		Handler: handler,
		client:  client,
		Version: minVersion,
		request: request,
	}
	session.Handler.StatusUpdate(session.Action, irma.StatusManualStarted)

	session.processSessionInfo()
	return session
}

func (client *Client) newSchemeSession(qr *irma.SchemeManagerRequest, handler Handler) SessionDismisser {
	session := &session{
		ServerURL: qr.URL,
		transport: irma.NewHTTPTransport(qr.URL),
		Action:    irma.ActionSchemeManager,
		Handler:   handler,
		client:    client,
	}
	session.Handler.StatusUpdate(session.Action, irma.StatusCommunicating)

	go session.managerSession()
	return session
}

// newQrSession creates and starts a new interactive IRMA session
func (client *Client) newQrSession(qr *irma.Qr, handler Handler, extern bool) SessionDismisser {
	u, _ := url.ParseRequestURI(qr.URL) // Qr validator already checked this for errors
	session := &session{
		ServerURL: qr.URL,
		Hostname:  u.Hostname(),
		transport: irma.NewHTTPTransport(qr.URL),
		Action:    irma.Action(qr.Type),
		Handler:   handler,
		client:    client,
		extern:	   extern,
	}

	session.Handler.StatusUpdate(session.Action, irma.StatusCommunicating)
	min := minVersion

	// Check if the action is one of the supported types
	switch session.Action {
	case irma.ActionDisclosing:
		session.request = &irma.DisclosureRequest{}
	case irma.ActionSigning:
		session.request = &irma.SignatureRequest{}
		min = &irma.ProtocolVersion{2, 5} // New ABS format is not backwards compatible with old irma server
	case irma.ActionIssuing:
		session.request = &irma.IssuanceRequest{}
	case irma.ActionUnknown:
		fallthrough
	default:
		session.fail(&irma.SessionError{ErrorType: irma.ErrorUnknownAction, Info: string(session.Action)})
		return nil
	}

	session.transport.SetHeader(irma.MinVersionHeader, min.String())
	session.transport.SetHeader(irma.MaxVersionHeader, maxVersion.String())
	if !strings.HasSuffix(session.ServerURL, "/") {
		session.ServerURL += "/"
	}

	go session.getSessionInfo()
	return session
}

// Core session methods

// getSessionInfo retrieves the first message in the IRMA protocol (only in interactive sessions)
func (session *session) getSessionInfo() {
	defer session.recoverFromPanic()

	session.Handler.StatusUpdate(session.Action, irma.StatusCommunicating)

	// Get the first IRMA protocol message and parse it
	err := session.transport.Get("", session.request)
	if err != nil {
		session.fail(err.(*irma.SessionError))
		return
	}

	session.processSessionInfo()
}

func serverName(hostname string, request irma.SessionRequest, conf *irma.Configuration) irma.TranslatedString {
	sn := irma.NewTranslatedString(&hostname)

	if ir, ok := request.(*irma.IssuanceRequest); ok {
		// If there is only one issuer in the current request, use its name as ServerName
		var iss irma.TranslatedString
		for _, credreq := range ir.Credentials {
			credIssuer := conf.Issuers[credreq.CredentialTypeID.IssuerIdentifier()].Name
			if !reflect.DeepEqual(credIssuer, iss) { // Can't just test pointer equality: credIssuer != iss
				if len(iss) != 0 {
					return sn
				}
				iss = credIssuer
			}
		}
		if len(iss) != 0 {
			return iss
		}
	}

	return sn
}

// processSessionInfo continues the session after all session state has been received:
// it checks if the session can be performed and asks the user for consent.
func (session *session) processSessionInfo() {
	defer session.recoverFromPanic()

	if err := session.checkAndUpateConfiguration(); err != nil {
		session.fail(err.(*irma.SessionError))
		return
	}

	baserequest := session.request.Base()
	confirmedProtocolVersion := baserequest.ProtocolVersion
	if confirmedProtocolVersion != nil {
		session.Version = confirmedProtocolVersion
	} else {
		session.Version = irma.NewVersion(2, 0)
		baserequest.ProtocolVersion = session.Version
	}

	session.ServerName = serverName(session.Hostname, session.request, session.client.Configuration)

	if session.Action == irma.ActionIssuing {
		ir := session.request.(*irma.IssuanceRequest)
		_, err := ir.GetCredentialInfoList(session.client.Configuration, session.Version)
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorUnknownIdentifier, Err: err})
			return
		}

		// Calculate singleton credentials to be removed
		ir.RemovalCredentialInfoList = irma.CredentialInfoList{}
		for _, credreq := range ir.Credentials {
			preexistingCredentials := session.client.attrs(credreq.CredentialTypeID)
			if len(preexistingCredentials) != 0 && preexistingCredentials[0].IsValid() && preexistingCredentials[0].CredentialType().IsSingleton {
				ir.RemovalCredentialInfoList = append(ir.RemovalCredentialInfoList, preexistingCredentials[0].Info())
			}
		}
	}

	candidates, missing := session.client.CheckSatisfiability(session.request.Disclosure().Disclose)
	if len(missing) > 0 {
		session.Handler.UnsatisfiableRequest(session.request, session.ServerName, missing)
		return
	}

	// Ask for permission to execute the session
	callback := PermissionHandler(func(proceed bool, choice *irma.DisclosureChoice) {
		session.choice = choice
		go session.doSession(proceed)
	})
	session.Handler.StatusUpdate(session.Action, irma.StatusConnected)
	switch session.Action {
	case irma.ActionDisclosing:
		session.Handler.RequestVerificationPermission(
			session.request.(*irma.DisclosureRequest), candidates, session.ServerName, callback)
	case irma.ActionSigning:
		session.Handler.RequestSignaturePermission(
			session.request.(*irma.SignatureRequest), candidates, session.ServerName, callback)
	case irma.ActionIssuing:
		session.Handler.RequestIssuancePermission(
			session.request.(*irma.IssuanceRequest), candidates, session.ServerName, callback)
	default:
		panic("Invalid session type") // does not happen, session.Action has been checked earlier
	}
}

// doSession performs the session: it computes all proofs of knowledge, constructs credentials in case of issuance,
// asks for the pin and performs the keyshare session, and finishes the session by either POSTing the result to the
// API server or returning it to the caller (in case of interactive and noninteractive sessions, respectively).
func (session *session) doSession(proceed bool) {
	defer session.recoverFromPanic()

	if !proceed {
		session.cancel()
		return
	}
	session.Handler.StatusUpdate(session.Action, irma.StatusCommunicating)

	// if disclosing request is originating from a non-IRMA verifier (identified via QRCode),
	// compute a verifiable presentation instead of an IRMA proof
	if session.IsExtern() && session.Action == irma.ActionDisclosing {
		message, err := session.getVerifiablePresentation()
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
			return
		}
		session.sendResponse(message)
		return
	}

	// For VC testing purposes, skip keyshare protocol
	if !session.Distributed() || session.IsExtern() {
		message, err := session.getProof()
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
			return
		}
		session.sendResponse(message)
	} else {
		var err error
		session.builders, session.attrIndices, session.issuerProofNonce, err = session.getBuilders()
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
		}
		startKeyshareSession(
			session,
			session.Handler,
			session.builders,
			session.request,
			session.client.Configuration,
			session.client.keyshareServers,
			session.issuerProofNonce,
			session.timestamp,
		)
	}
}

const LDVerifiableCredential = "https://www.w3.org/2018/credentials/v1"
const LDContextDisclosureRequest = "https://irma.app/ld/request/disclosure/v2"
const LDContextIssuingRequest = "https://irma.app/ld/request/issuing/v2"

func (session *session) getVerifiablePresentation() (interface{}, error) {
	var err error
	var attrValues [][]*irma.DisclosedAttribute
	index := 0

	// initialize verifiable presentation object
	vcPres := irma.VerifiablePresentation{}
	vcPres.LDContext = [2]string{LDVerifiableCredential, LDContextDisclosureRequest}
	vcPres.Type = append(vcPres.Type, "VerifiablePresentation")

	// get ProofList of disclosed credentials
	builders, choices, timestamp, err := session.client.ProofBuilders(session.choice, session.request)
	if err != nil {
		return nil, err
	}

	proofList := builders.BuildProofList(session.request.Base().GetContext(), session.request.GetNonce(timestamp), false)

	disjunctions := session.request.Disclosure()

	disclosure := &irma.Disclosure{
		Proofs:  proofList,
		Indices: choices,
	}

	vcPres.Proof.ProofMsg = disclosure
	vcPres.Proof.Created = time.Now().Format(time.RFC3339)
	vcPres.Proof.Type = "AnonCredPresentationProofv1"

	_, attrValues, err = disclosure.DisclosedAttributes(session.client.Configuration, disjunctions.Disclose)

	// iterate over each attribute to determine cred types in disclosure request
	credTypes := make(map[irma.CredentialTypeIdentifier]bool)
	_ = disjunctions.Disclose.Iterate(func(attr *irma.AttributeRequest) error {
		credid := attr.Type.CredentialTypeIdentifier()
		credTypes[credid] = true
		return nil
	})

	// For each credential type within a disclosing session, a derived VC needs to be created
	for credType, _ := range credTypes {

		// Metadata attribute from related ProofD object
		metadata := irma.MetadataFromInt(proofList[index].(*gabi.ProofD).ADisclosed[1], session.client.Configuration) // index 1 is metadata attribute

		// Create derived credential
		vc := irma.VerifiableCredential{}

		// Context information
		vc.LDContext = [2]string{LDVerifiableCredential, LDContextDisclosureRequest}

		// Type information
		vc.Type = make([]string, 1)
		vc.Type[0] = "VerifiableCredential"
		vc.Type = append(vc.Type, credType.Name())

		// Credential schema information
		vc.Schema = append(vc.Schema, irma.VCSchema{Identifier: irma.VCServerURL + "schema/" + strings.Replace(credType.String(), ".", "/", -1), Type: credType.Name()})

		// Proof information
		//vc.Proof.Type = "AnonCredDerivedCredentialv1"
		//vc.Proof.Created = metadata.SigningDate().Format(time.RFC3339) // credType SigningDate().Format(time.RFC3339)
		//vc.Proof.ProofMsg = proofList[index].(*gabi.ProofD).A          // randomized signature

		// Issuer information
		issuerID := credType.IssuerIdentifier().Name()
		metadataPk, _ := metadata.PublicKey()
		vc.Issuer = irma.VCServerURL + "issuer/" + strings.Replace(issuerID, ".", "/", -1) + "/" + fmt.Sprint(metadataPk.Counter)

		// Expiration date
		vc.ExpirationDate = metadata.Expiry().Format(time.RFC3339)

		// For each disclosed credential create one subject
		vcSubject := irma.VCSubject{}
		vcSubject.Attributes = make(map[string]irma.TranslatedString)

		// Filter attributes belonging to this credentialType
		var disclosed []*irma.DisclosedAttribute
		for _, l := range attrValues {
			for _, ll := range l {
				s1 := ll.Identifier.CredentialTypeIdentifier().String()
				s2 := metadata.CredentialType().Identifier().String()
				if strings.Compare(s1, s2) == 0 {
					disclosed = append(disclosed, ll)
				}
			}
		}

		// Map IRMA attributes to VC attributes
		for _, value := range disclosed {
			vcSubject.Attributes[value.Identifier.Name()] = irma.NewVCTranslatedString(value.Value["en"])
		}

		// Convert attributes tag to name of credential type id
		byteSubject, _ := json.Marshal(vcSubject)
		obj := map[string]interface{}{}
		_ = json.Unmarshal([]byte(byteSubject), &obj)
		obj[credType.Name()] = obj["attributes"]
		delete(obj, "attributes")
		vc.CredentialSubjects = append(vc.CredentialSubjects, obj)

		vcPres.DerivedCredentials = append(vcPres.DerivedCredentials, vc)

		index++
	}

	return vcPres, err
}

type disclosureResponse string

// sendResponse sends the proofs of knowledge of the hidden attributes and/or the secret key, or the constructed
// attribute-based signature, to the API server.
func (session *session) sendResponse(message interface{}) {
	var log *LogEntry
	var err error
	var messageJson []byte

	switch session.Action {
	case irma.ActionSigning:
		irmaSignature, err := session.request.(*irma.SignatureRequest).SignatureFromMessage(message, session.timestamp)
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorSerialization, Info: "Type assertion failed"})
			return
		}

		messageJson, err = json.Marshal(irmaSignature)
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorSerialization, Err: err})
			return
		}

		if session.IsInteractive() {
			var response disclosureResponse
			if err = session.transport.Post("proofs", &response, irmaSignature); err != nil {
				session.fail(err.(*irma.SessionError))
				return
			}
			if response != "VALID" {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorRejected, Info: string(response)})
				return
			}
		}
		log, _ = session.createLogEntry(message) // TODO err
	case irma.ActionDisclosing:

		messageJson, err = json.Marshal(message)
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorSerialization, Err: err})
			return
		}
		if session.IsInteractive() {
			var response disclosureResponse

			// VC: For validation purposes, send presentation from IRMA client to irma server
			switch message.(type) {
			case irma.VerifiablePresentation:
				session.transport.SetHeader(irma.VCHeader, "yes")
				if err = session.transport.Post("proofs", &response, message); err != nil {
					session.fail(err.(*irma.SessionError))
					return
				}
			default:
				if err = session.transport.Post("proofs", &response, message); err != nil {
					session.fail(err.(*irma.SessionError))
					return
				}
			}
			if response != "VALID" {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorRejected, Info: string(response)})
				return
			}
		}
		log, _ = session.createLogEntry(message) // TODO err
	case irma.ActionIssuing:

		if !irma.IssueVC {
			response := []*gabi.IssueSignatureMessage{}
			if err = session.transport.Post("commitments", &response, message); err != nil {
				session.fail(err.(*irma.SessionError))
				return
			}
			if err = session.client.ConstructCredentials(response, session.request.(*irma.IssuanceRequest), session.builders); err != nil {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
				return
			}
		} else {
			response := irma.VerifiableCredential{}
			session.transport.SetHeader(irma.VCHeader, "yes")

			if err = session.transport.Post("commitments", &response, message); err != nil {
				session.fail(err.(*irma.SessionError))
				return
			}
			if err = session.client.ConstructVerifiableCredentials(response, session.request.(*irma.IssuanceRequest), session.builders); err != nil {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
				return
			}
		}
		log, _ = session.createLogEntry(message) // TODO err
	}

	session.client.addLogEntry2(log)

	if session.Action == irma.ActionIssuing {
		session.client.handler.UpdateAttributes()
	}

	session.done = true
	session.Handler.Success(string(messageJson))
}

func (session *session) logVC(interr interface{}) {
	messageJson, _ := json.Marshal(interr)
	session.Handler.Success(string(messageJson))
}

// ConstructVerifiableCredentials is able to handle VCs, by marshalling []gabi.IssueSignatureMessage
// Reusing IRMA computation to extract credentials from signature to store them as IRMA credentials
func (client *Client) ConstructVerifiableCredentials(msg irma.VerifiableCredential, request *irma.IssuanceRequest, builders gabi.ProofBuilderList) error {
	if len(msg.Proof.ProofMsg.([]interface{})) > len(builders) {
		return errors.New("Received unexpected amount of signatures")
	}

	// Extract gabi.IssueSignatureMessage array from VC
	sigByte, err := json.Marshal(msg.Proof.ProofMsg)
	var sigs []gabi.IssueSignatureMessage
	err = json.Unmarshal(sigByte, &sigs)
	if err != nil {
		return errors.New(err)
	}

	// First collect all credentials in a slice, so that if one of them induces an error,
	// we save none of them to fail the session cleanly
	gabicreds := []*gabi.Credential{}
	offset := 0
	for i, builder := range builders {
		credbuilder, ok := builder.(*gabi.CredentialBuilder)
		if !ok { // Skip builders of disclosure proofs
			offset++
			continue
		}

		sig := sigs[i-offset]

		attrs, err := request.Credentials[i-offset].AttributeList(client.Configuration, irma.GetMetadataVersion(request.Base().ProtocolVersion))
		if err != nil {
			return err
		}
		cred, err := credbuilder.ConstructCredential(&sig, attrs.Ints)
		if err != nil {
			return err
		}
		gabicreds = append(gabicreds, cred)
	}

	for _, gabicred := range gabicreds {
		newcred, err := newCredential(gabicred, client.Configuration)
		if err != nil {
			return err
		}
		if err = client.addCredential(newcred, true); err != nil {
			return err
		}
	}

	return nil
}

func (client *Client) addLogEntry2(entry *LogEntry) error {
	return nil
}

// managerSession performs a "session" in which a new scheme manager is added (asking for permission first).
func (session *session) managerSession() {
	defer session.recoverFromPanic()

	// We have to download the scheme manager description.xml here before installing it,
	// because we need to show its contents (name, description, website) to the user
	// when asking installation permission.
	manager, err := irma.DownloadSchemeManager(session.ServerURL)
	if err != nil {
		session.Handler.Failure(&irma.SessionError{ErrorType: irma.ErrorConfigurationDownload, Err: err})
		return
	}

	session.Handler.RequestSchemeManagerPermission(manager, func(proceed bool) {
		if !proceed {
			session.Handler.Cancelled() // No need to DELETE session here
			return
		}
		if err := session.client.Configuration.InstallSchemeManager(manager, nil); err != nil {
			session.Handler.Failure(&irma.SessionError{ErrorType: irma.ErrorConfigurationDownload, Err: err})
			return
		}

		// Update state and inform user of success
		session.client.handler.UpdateConfiguration(
			&irma.IrmaIdentifierSet{
				SchemeManagers:  map[irma.SchemeManagerIdentifier]struct{}{manager.Identifier(): {}},
				Issuers:         map[irma.IssuerIdentifier]struct{}{},
				CredentialTypes: map[irma.CredentialTypeIdentifier]struct{}{},
			},
		)
		session.Handler.Success("")
	})
	return
}

// Response calculation methods

// getBuilders computes the builders for disclosure proofs or secretkey-knowledge proof (in case of disclosure/signing
// and issuing respectively).
func (session *session) getBuilders() (gabi.ProofBuilderList, irma.DisclosedAttributeIndices, *big.Int, error) {
	var builders gabi.ProofBuilderList
	var err error
	var issuerProofNonce *big.Int
	var choices irma.DisclosedAttributeIndices

	switch session.Action {
	case irma.ActionSigning, irma.ActionDisclosing:
		builders, choices, session.timestamp, err = session.client.ProofBuilders(session.choice, session.request)
	case irma.ActionIssuing:
		builders, choices, issuerProofNonce, err = session.client.IssuanceProofBuilders(session.request.(*irma.IssuanceRequest), session.choice)
	}

	return builders, choices, issuerProofNonce, err
}

// getProofs computes the disclosure proofs or secretkey-knowledge proof (in case of disclosure/signing
// and issuing respectively) to be sent to the server.
func (session *session) getProof() (interface{}, error) {
	var message interface{}
	var err error

	switch session.Action {
	case irma.ActionSigning, irma.ActionDisclosing:
		message, session.timestamp, err = session.client.Proofs(session.choice, session.request)
	case irma.ActionIssuing:
		if irma.IssueVC {
			message, session.builders, err = session.client.IssueCommitmentsVC(session.request.(*irma.IssuanceRequest), session.choice)
		} else {
			message, session.builders, err = session.client.IssueCommitments(session.request.(*irma.IssuanceRequest), session.choice)
		}
	}

	return message, err
}

func (client *Client) IssueCommitmentsVC(request *irma.IssuanceRequest, choice *irma.DisclosureChoice,
) (*irma.VerifiableCredential, gabi.ProofBuilderList, error) {
	builders, choices, issuerProofNonce, err := client.IssuanceProofBuilders(request, choice)
	if err != nil {
		return nil, nil, err
	}

	vc := irma.VerifiableCredential{}
	vc.LDContext = [2]string{LDVerifiableCredential, LDContextIssuingRequest}
	// type
	vc.Type = make([]string, 1)
	vc.Type[0] = "VerifiableCredential"

	//irmaVCServerURL :=  client.Configuration.SchemeManagers[request.Credentials[0].CredentialTypeID.IssuerIdentifier().SchemeManagerIdentifier()].TypeServerURL
	irmaVCServerURL := "http://localhost:8089/"

	issuerID := request.Credentials[0].CredentialTypeID.IssuerIdentifier()

	pkIndices, _ := client.Configuration.PublicKeyIndices(issuerID)
	highest := -1
	for current := range pkIndices {
		if current > highest {
			highest = current
		}
	}
	highestStr := strconv.Itoa(highest)

	vc.Issuer = issuerID.String()
	vc.Issuer = irmaVCServerURL + "issuer/" + strings.Replace(vc.Issuer, ".", "/", -1) + "/" + highestStr

	layout := "2006-01-02T15:04:05Z"
	vc.IssuanceDate = time.Now().Format(layout)

	for _, cred := range request.Credentials {
		// types
		vc.Type = append(vc.Type, cred.CredentialTypeID.Name())
		vcSubject := irma.VCSubject{}

		// create new translated string that has a rawValue, en and nl key
		vcSubject.Attributes = make(map[string]irma.TranslatedString)
		for key, value := range cred.Attributes {
			vcSubject.Attributes[key] = irma.NewVCTranslatedString(value)
		}

		// convert attributes tag to name of credential type id
		byteSubject, _ := json.Marshal(vcSubject)
		obj := map[string]interface{}{}
		_ = json.Unmarshal([]byte(byteSubject), &obj)
		obj[cred.CredentialTypeID.Name()] = obj["attributes"]
		delete(obj, "attributes")
		vc.CredentialSubjects = append(vc.CredentialSubjects, obj)
	}

	vc.Proof.Type = "IRMACommitment"
	vc.Proof.Created = time.Now().Format(time.RFC3339)
	vc.Proof.ProofMsg = &irma.IssueCommitmentMessage{
		IssueCommitmentMessage: &gabi.IssueCommitmentMessage{
			Proofs: builders.BuildProofList(request.GetContext(), request.GetNonce(nil), false),
			Nonce2: issuerProofNonce,
		},
		Indices: choices,
	}

	return &vc, builders, nil
}




// Helper functions

// checkKeyshareEnrollment checks if we are enrolled into all involved keyshare servers,
// and aborts the session if not
func (session *session) checkKeyshareEnrollment() bool {
	for id := range session.request.Identifiers().SchemeManagers {
		distributed := session.client.Configuration.SchemeManagers[id].Distributed()
		_, enrolled := session.client.keyshareServers[id]
		if distributed && !enrolled {
			session.Handler.KeyshareEnrollmentMissing(id)
			return false
		}
	}
	return true
}

func (session *session) checkAndUpateConfiguration() error {
	// Download missing credential types/issuers/public keys from the scheme manager
	downloaded, err := session.client.Configuration.Download(session.request)
	if uerr, ok := err.(*irma.UnknownIdentifierError); ok {
		return &irma.SessionError{ErrorType: uerr.ErrorType, Err: uerr}
	} else if err != nil {
		return &irma.SessionError{ErrorType: irma.ErrorConfigurationDownload, Err: err}
	}
	if downloaded != nil && !downloaded.Empty() {
		if err = session.client.ConfigurationUpdated(downloaded); err != nil {
			return err
		}
		session.client.handler.UpdateConfiguration(downloaded)
	}

	// Check if we are enrolled into all involved keyshare servers
	// Skip if external request
	if !session.IsExtern() && !session.checkKeyshareEnrollment(){
		return &irma.SessionError{ErrorType: irma.ErrorKeyshare}
	}

	if err = session.request.Disclosure().Disclose.Validate(session.client.Configuration); err != nil {
		return &irma.SessionError{ErrorType: irma.ErrorInvalidRequest}
	}

	return nil
}

// IsInteractive returns whether this session uses an API server or not.
func (session *session) IsInteractive() bool {
	return session.ServerURL != ""
}

func (session *session) IsExtern() bool {
	return session.extern
}

// Distributed returns whether or not this session involves a keyshare server.
func (session *session) Distributed() bool {
	var smi irma.SchemeManagerIdentifier
	if session.Action == irma.ActionIssuing {
		for _, credreq := range session.request.(*irma.IssuanceRequest).Credentials {
			smi = credreq.CredentialTypeID.IssuerIdentifier().SchemeManagerIdentifier()
			if session.client.Configuration.SchemeManagers[smi].Distributed() {
				return true
			}
		}
	}

	if session.choice == nil || session.choice.Attributes == nil {
		return false
	}

	for _, attrlist := range session.choice.Attributes {
		for _, ai := range attrlist {
			smi = ai.Type.CredentialTypeIdentifier().IssuerIdentifier().SchemeManagerIdentifier()
			if session.client.Configuration.SchemeManagers[smi].Distributed() {
				return true
			}
		}
	}

	return false
}

// Session lifetime functions

func (session *session) recoverFromPanic() {
	if e := recover(); e != nil {
		if session.Handler != nil {
			session.Handler.Failure(panicToError(e))
		}
	}
}

func panicToError(e interface{}) *irma.SessionError {
	var info string
	switch x := e.(type) {
	case string:
		info = x
	case error:
		info = x.Error()
	case fmt.Stringer:
		info = x.String()
	default: // nop
	}
	fmt.Println("Panic: " + info)
	return &irma.SessionError{ErrorType: irma.ErrorPanic, Info: info + "\n\n" + string(debug.Stack())}
}

// Idempotently send DELETE to remote server, returning whether or not we did something
func (session *session) delete() bool {
	if !session.done {
		if session.IsInteractive() {
			session.transport.Delete()
		}
		session.done = true
		return true
	}
	return false
}

func (session *session) fail(err *irma.SessionError) {
	if session.delete() {
		err.Err = errors.Wrap(err.Err, 0)
		session.Handler.Failure(err)
	}
}

func (session *session) cancel() {
	if session.delete() {
		session.Handler.Cancelled()
	}
}

func (session *session) Dismiss() {
	session.cancel()
}

// Keyshare session handler methods

func (session *session) KeyshareDone(message interface{}) {
	switch session.Action {
	case irma.ActionSigning:
		fallthrough
	case irma.ActionDisclosing:
		session.sendResponse(&irma.Disclosure{
			Proofs:  message.(gabi.ProofList),
			Indices: session.attrIndices,
		})
	case irma.ActionIssuing:
		session.sendResponse(&irma.IssueCommitmentMessage{
			IssueCommitmentMessage: message.(*gabi.IssueCommitmentMessage),
			Indices:                session.attrIndices,
		})
	}
}

func (session *session) KeyshareCancelled() {
	session.cancel()
}

func (session *session) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	session.Handler.KeyshareEnrollmentIncomplete(manager)
}

func (session *session) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	session.Handler.KeyshareEnrollmentDeleted(manager)
}

func (session *session) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	session.Handler.KeyshareBlocked(manager, duration)
}

func (session *session) KeyshareError(manager *irma.SchemeManagerIdentifier, err error) {
	var serr *irma.SessionError
	var ok bool
	if serr, ok = err.(*irma.SessionError); !ok {
		serr = &irma.SessionError{ErrorType: irma.ErrorKeyshare, Err: err}
	} else {
		serr.ErrorType = irma.ErrorKeyshare
	}
	session.fail(serr)
}

func (session *session) KeysharePin() {
	session.Handler.StatusUpdate(session.Action, irma.StatusConnected)
}

func (session *session) KeysharePinOK() {
	session.Handler.StatusUpdate(session.Action, irma.StatusCommunicating)
}
