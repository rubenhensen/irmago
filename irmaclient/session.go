package irmaclient

import (
	"encoding/json"
	"fmt"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
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
	StatusUpdate(action irma.Action, status irma.ClientStatus)
	ClientReturnURLSet(clientReturnURL string)
	PairingRequired(pairingCode string)
	Success(result string)
	Cancelled()
	Failure(err *irma.SessionError)

	KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int)
	KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier)
	KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier)
	KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier)

	RequestIssuancePermission(request *irma.IssuanceRequest,
		satisfiable bool,
		candidates [][]DisclosureCandidates,
		requestorInfo *irma.RequestorInfo,
		callback PermissionHandler)
	RequestVerificationPermission(request *irma.DisclosureRequest,
		satisfiable bool,
		candidates [][]DisclosureCandidates,
		requestorInfo *irma.RequestorInfo,
		callback PermissionHandler)
	RequestSignaturePermission(request *irma.SignatureRequest,
		satisfiable bool,
		candidates [][]DisclosureCandidates,
		requestorInfo *irma.RequestorInfo,
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
	Action        irma.Action
	Handler       Handler
	Version       *irma.ProtocolVersion
	RequestorInfo *irma.RequestorInfo

	token          string
	choice         *irma.DisclosureChoice
	attrIndices    irma.DisclosedAttributeIndices
	client         *Client
	request        irma.SessionRequest
	done           <-chan struct{}
	prepRevocation chan error // used when nonrevocation preprocessing is done

	next               *session
	implicitDisclosure [][]*irma.AttributeIdentifier

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
	extern bool
}

type sessions struct {
	client   *Client
	sessions map[string]*session
}

// We implement the handler for the keyshare protocol
var _ keyshareSessionHandler = (*session)(nil)

// Supported protocol versions. Minor version numbers should be sorted.
var supportedVersions = map[int][]int{
	2: {
		4, // old protocol with legacy session requests
		5, // introduces condiscon feature
		6, // introduces nonrevocation proofs
		7, // introduces chained sessions
		8, // introduces session binding
	},
}

// Session constructors

// NewSession starts a new IRMA session, given (along with a handler to pass feedback to) a session request.
// When the request is not suitable to start an IRMA session from, it calls the Failure method of the specified Handler.
func (client *Client) NewSession(sessionrequest string, handler Handler) SessionDismisser {
	bts := []byte(sessionrequest)

	qr := &irma.Qr{}
	if err := json.Unmarshal(bts, qr); err == nil && qr.IsQr() {
		if err = qr.Validate(); err != nil {
			handler.Failure(&irma.SessionError{ErrorType: irma.ErrorInvalidRequest, Err: err})
			return nil
		}
		return client.newQrSession(qr, handler, irma.IssueVC)
	}

	qrSovrin := &irma.QrSovrin{}
	if err := json.Unmarshal(bts, qrSovrin); err == nil && qr.IsQr() {
		if err = qr.Validate(); err != nil {
			handler.Failure(&irma.SessionError{ErrorType: irma.ErrorInvalidRequest, Err: err})
			return nil
		}
		qr.Type = qrSovrin.Type
		qr.URL = qrSovrin.URL
		return client.newQrSession(qr, handler, true)
	}

	sigRequest := &irma.SignatureRequest{}
	if err := json.Unmarshal(bts, sigRequest); err == nil && sigRequest.IsSignatureRequest() {
		if err = sigRequest.Validate(); err != nil {
			handler.Failure(&irma.SessionError{ErrorType: irma.ErrorInvalidRequest, Err: err})
			return nil
		}
		return client.newManualSession(sigRequest, handler, irma.ActionSigning)
	}

	disclosureRequest := &irma.DisclosureRequest{}
	if err := json.Unmarshal(bts, disclosureRequest); err == nil && disclosureRequest.IsDisclosureRequest() {
		if err = disclosureRequest.Validate(); err != nil {
			handler.Failure(&irma.SessionError{ErrorType: irma.ErrorInvalidRequest, Err: err})
			return nil
		}
		return client.newManualSession(disclosureRequest, handler, irma.ActionDisclosing)
	}

	handler.Failure(&irma.SessionError{ErrorType: irma.ErrorInvalidRequest, Info: "session request of unsupported type"})
	return nil
}

// newManualSession starts a manual session, given a signature request in JSON and a handler to pass messages to
func (client *Client) newManualSession(request irma.SessionRequest, handler Handler, action irma.Action) SessionDismisser {
	client.PauseJobs()

	doneChannel := make(chan struct{}, 1)
	doneChannel <- struct{}{}
	close(doneChannel)
	session := &session{
		Action:         action,
		Handler:        handler,
		client:         client,
		Version:        client.minVersion,
		request:        request,
		done:           doneChannel,
		prepRevocation: make(chan error),
	}
	client.sessions.add(session)
	session.Handler.StatusUpdate(session.Action, irma.ClientStatusManualStarted)

	session.processSessionInfo()
	return session
}

// newQrSession creates and starts a new interactive IRMA session
func (client *Client) newQrSession(qr *irma.Qr, handler Handler, extern bool) *session {
	if qr.Type == irma.ActionRedirect {
		newqr := &irma.Qr{}
		transport := irma.NewHTTPTransport("", !client.Preferences.DeveloperMode)
		if err := transport.Post(qr.URL, newqr, struct{}{}); err != nil {
			handler.Failure(&irma.SessionError{ErrorType: irma.ErrorTransport, Err: errors.Wrap(err, 0)})
			return nil
		}
		if newqr.Type == irma.ActionRedirect { // explicitly avoid infinite recursion
			handler.Failure(&irma.SessionError{ErrorType: irma.ErrorInvalidRequest, Err: errors.New("infinite static QR recursion")})
			return nil
		}
		return client.newQrSession(newqr, handler)
	}

	client.PauseJobs()

	u, _ := url.ParseRequestURI(qr.URL) // Qr validator already checked this for errors
	doneChannel := make(chan struct{}, 1)
	doneChannel <- struct{}{}
	close(doneChannel)
	session := &session{
		ServerURL:      qr.URL,
		Hostname:       u.Hostname(),
		RequestorInfo:  requestorInfo(qr.URL, client.Configuration),
		transport:      irma.NewHTTPTransport(qr.URL, !client.Preferences.DeveloperMode),
		Action:         qr.Type,
		Handler:        handler,
		client:         client,
		done:           doneChannel,
		prepRevocation: make(chan error),
		extern:         extern,
	}
	client.sessions.add(session)

	session.Handler.StatusUpdate(session.Action, irma.ClientStatusCommunicating)
	min := client.minVersion

	// Check if the action is one of the supported types
	switch session.Action {
	case irma.ActionDisclosing:
		session.request = &irma.DisclosureRequest{}
	case irma.ActionSigning:
		session.request = &irma.SignatureRequest{}
		min = &irma.ProtocolVersion{Major: 2, Minor: 5} // New ABS format is not backwards compatible with old irma server
	case irma.ActionIssuing:
		session.request = &irma.IssuanceRequest{}
	case irma.ActionUnknown:
		fallthrough
	default:
		session.fail(&irma.SessionError{ErrorType: irma.ErrorUnknownAction, Info: string(session.Action)})
		return nil
	}

	session.transport.SetHeader(irma.MinVersionHeader, min.String())
	session.transport.SetHeader(irma.MaxVersionHeader, client.maxVersion.String())

	// From protocol version 2.8 also an authorization header must be included.
	if client.maxVersion.Above(2, 7) {
		clientAuth := common.NewSessionToken()
		session.transport.SetHeader(irma.AuthorizationHeader, clientAuth)
	}

	if !strings.HasSuffix(session.ServerURL, "/") {
		session.ServerURL += "/"
	}

	go session.getSessionInfo()
	return session
}

// Core session methods

// getSessionInfo retrieves the first message in the IRMA protocol (only in interactive sessions)
// If needed, it also handles pairing.
func (session *session) getSessionInfo() {
	defer session.recoverFromPanic()

	session.Handler.StatusUpdate(session.Action, irma.ClientStatusCommunicating)

	// Get the first IRMA protocol message and parse it
	cr := &irma.ClientSessionRequest{
		Request: session.request, // As request is an interface, it needs to be initialized with a specific instance.
	}
	// UnmarshalJSON of ClientSessionRequest takes into account legacy protocols, so we do not have to check that here.
	err := session.transport.Get("", cr)
	if err != nil {
		session.fail(err.(*irma.SessionError))
		return
	}

	// Check whether pairing is needed, and if so, wait for it to be completed.
	if cr.Options.PairingMethod != irma.PairingMethodNone {
		if err = session.handlePairing(cr.Options.PairingCode); err != nil {
			session.fail(err.(*irma.SessionError))
			return
		}
	}

	session.processSessionInfo()
}

func (session *session) handlePairing(pairingCode string) error {
	session.Handler.PairingRequired(pairingCode)

	statuschan := make(chan irma.ServerStatus)
	errorchan := make(chan error)

	go irma.WaitStatusChanged(session.transport, irma.ServerStatusPairing, statuschan, errorchan)
	select {
	case status := <-statuschan:
		if status == irma.ServerStatusConnected {
			return session.transport.Get("request", session.request)
		} else {
			return &irma.SessionError{ErrorType: irma.ErrorPairingRejected}
		}
	case err := <-errorchan:
		if serr, ok := err.(*irma.SessionError); ok {
			return serr
		}
		return &irma.SessionError{
			ErrorType: irma.ErrorServerResponse,
			Info:      "Pairing aborted by server",
			Err:       err,
		}
	}
}

func requestorInfo(serverURL string, conf *irma.Configuration) *irma.RequestorInfo {
	if serverURL == "" {
		return nil
	}
	u, _ := url.ParseRequestURI(serverURL) // Qr validator already checked this for errors
	hostname := u.Hostname()
	info, present := conf.Requestors[hostname]

	if (u.Scheme == "https" || !common.ForceHTTPS) && present &&
		(info.ValidUntil == nil || info.ValidUntil.After(irma.Timestamp(time.Now()))) {
		return info
	} else {
		return irma.NewRequestorInfo(hostname)
	}
}

func checkKey(conf *irma.Configuration, issuer irma.IssuerIdentifier, counter uint) error {
	id := fmt.Sprintf("%s-%d", issuer, counter)
	pk, err := conf.PublicKey(issuer, counter)
	if err != nil {
		return err
	}
	if pk == nil {
		return errors.Errorf("credential signed with unknown public key %s", id)
	}
	if time.Now().Unix() > pk.ExpiryDate {
		return errors.Errorf("credential signed with expired key %s", id)
	}
	return nil
}

// processSessionInfo continues the session after all session state has been received:
// it checks if the session can be performed and asks the user for consent.
func (session *session) processSessionInfo() {
	defer session.recoverFromPanic()

	if err := session.checkAndUpdateConfiguration(); err != nil {
		session.fail(err.(*irma.SessionError))
		return
	}

	baserequest := session.request.Base()
	if baserequest.DevelopmentMode && !session.client.Preferences.DeveloperMode {
		session.fail(&irma.SessionError{
			ErrorType: irma.ErrorInvalidRequest,
			Info:      "server running in developer mode: either switch to production mode, or enable developer mode in IRMA app",
		})
		return
	}
	confirmedProtocolVersion := baserequest.ProtocolVersion
	if confirmedProtocolVersion != nil {
		session.Version = confirmedProtocolVersion
	} else {
		session.Version = irma.NewVersion(2, 0)
		baserequest.ProtocolVersion = session.Version
	}

	if session.Action == irma.ActionIssuing {
		ir := session.request.(*irma.IssuanceRequest)
		issuedAt := time.Now()
		_, err := ir.GetCredentialInfoList(session.client.Configuration, session.Version, issuedAt)
		if err != nil {
			if err, ok := err.(*irma.SessionError); ok {
				session.fail(err)
			} else {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorUnknownIdentifier, Err: err})
			}
			return
		}

		// Calculate singleton credentials to be removed
		ir.RemovalCredentialInfoList = irma.CredentialInfoList{}
		for _, credreq := range ir.Credentials {
			err := checkKey(session.client.Configuration, credreq.CredentialTypeID.IssuerIdentifier(), credreq.KeyCounter)
			if err != nil {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorInvalidRequest, Err: err})
				return
			}
			preexistingCredentials := session.client.attrs(credreq.CredentialTypeID)
			if len(preexistingCredentials) != 0 && preexistingCredentials[0].IsValid() && preexistingCredentials[0].CredentialType().IsSingleton {
				ir.RemovalCredentialInfoList = append(ir.RemovalCredentialInfoList, preexistingCredentials[0].Info())
			}
		}
	}

	// Prepare and update all revocation state asynchroniously.
	// At this point, the user is waiting on us to present her with candidate attributes to choose from.
	// We don't want to take too long, but we also preferably want to update our nonrevocation witnesses
	// before we start calculating candidate attributes, as the update process may revoke some of
	// our credentials: if updating finishes after the candidate computation, it could happen that
	// options corresponding to revoked credentials are presented to the user. If she chooses those
	// then the session would fail.
	// So we wait a small amount of time for the update process to finish, so that
	// if it finishes in time, then credentials that have been revoked can be excluded from the
	// candidate calculation.
	go func() {
		session.prepRevocation <- session.client.NonrevPrepare(session.request)
	}()
	select {
	case err := <-session.prepRevocation:
		irma.Logger.Debug("revocation witnesses updated before candidate computation")
		close(session.prepRevocation)
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorRevocation, Err: err})
			return
		}
	case <-time.After(time.Duration(irma.RevocationParameters.ClientUpdateTimeout) * time.Millisecond):
		irma.Logger.Debug("starting candidate computation before revocation witnesses updating finished")
	}

	// Handle ClientReturnURL if one is found in the session request
	if session.request.Base().ClientReturnURL != "" {
		session.Handler.ClientReturnURLSet(session.request.Base().ClientReturnURL)
	}

	session.requestPermission()
}

func (session *session) requestPermission() {
	candidates, satisfiable, err := session.client.Candidates(session.request)
	if err != nil {
		session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
		return
	}

	session.Handler.StatusUpdate(session.Action, irma.ClientStatusConnected)

	// Ask for permission to execute the session
	switch session.Action {
	case irma.ActionDisclosing:
		session.Handler.RequestVerificationPermission(
			session.request.(*irma.DisclosureRequest), satisfiable, candidates, session.RequestorInfo, session.doSession)
	case irma.ActionSigning:
		session.Handler.RequestSignaturePermission(
			session.request.(*irma.SignatureRequest), satisfiable, candidates, session.RequestorInfo, session.doSession)
	case irma.ActionIssuing:
		session.Handler.RequestIssuancePermission(
			session.request.(*irma.IssuanceRequest), satisfiable, candidates, session.RequestorInfo, session.doSession)
	default:
		panic("Invalid session type") // does not happen, session.Action has been checked earlier
	}
}

// doSession performs the session: it computes all proofs of knowledge, constructs credentials in case of issuance,
// asks for the pin and performs the keyshare session, and finishes the session by either POSTing the result to the
// API server or returning it to the caller (in case of interactive and noninteractive sessions, respectively).
func (session *session) doSession(proceed bool, choice *irma.DisclosureChoice) {
	defer session.recoverFromPanic()

	if !proceed {
		session.cancel()
		return
	}

	// If this is a session in a chain of sessions, also disclose all attributes disclosed in previous sessions
	if session.implicitDisclosure != nil {
		choice.Attributes = append(choice.Attributes, session.implicitDisclosure...)
	}

	session.choice = choice
	if err := session.choice.Validate(); err != nil {
		session.fail(&irma.SessionError{ErrorType: irma.ErrorRequiredAttributeMissing, Err: err})
		return
	}
	session.Handler.StatusUpdate(session.Action, irma.ClientStatusCommunicating)

	// wait for revocation preparation to finish
	err := <-session.prepRevocation
	if err != nil {
		session.fail(&irma.SessionError{ErrorType: irma.ErrorRevocation, Err: err})
		return
	}

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
		session.finish(false)
	} else {
		var err error
		session.builders, session.attrIndices, session.issuerProofNonce, err = session.getBuilders()
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
		}
		startKeyshareSession(
			session,
			session.client,
			session.Handler,
			session.builders,
			session.request,
			session.implicitDisclosure,
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
	vcPres.Proof.Type = "IRMAZKPPresentationProofv1"

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
		vc.Schema = append(vc.Schema, irma.VCSchema{Identifier: irma.VCServerURL + "schema/" + strings.Replace(credType.String(), ".", "/", -1), Type: "JsonSchemaValidator2018"})

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
	var path string
	var ourResponse interface{}
	serverResponse := &irma.ServerSessionResponse{ProtocolVersion: session.Version, SessionType: session.Action}

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
		ourResponse = irmaSignature
		path = "proofs"
	case irma.ActionDisclosing:

		messageJson, err = json.Marshal(message)
		if err != nil {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorSerialization, Err: err})
			return
		}
		ourResponse = message
		path = "proofs"
	case irma.ActionIssuing:
		ourResponse = message
		path = "commitments"
	}

	if session.IsInteractive() {
		if err = session.transport.Post(path, &serverResponse, ourResponse); err != nil {
			session.fail(err.(*irma.SessionError))
			return
		}
		if serverResponse.ProofStatus != irma.ProofStatusValid {
			session.fail(&irma.SessionError{ErrorType: irma.ErrorRejected, Info: string(serverResponse.ProofStatus)})
			return
		}
		if session.Action == irma.ActionIssuing && !irma.IssueVC {
			if err = session.client.ConstructCredentials(serverResponse.IssueSignatures, session.request.(*irma.IssuanceRequest), session.builders); err != nil {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
				return
			}
		}
		if session.Action == irma.ActionIssuing && irma.IssueVC {
			if err = session.client.ConstructVerifiableCredentials(serverResponse.IssueSignatures, session.request.(*irma.IssuanceRequest), session.builders); err != nil {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
				return
			}
		}
	}

	log, err = session.createLogEntry(message)
	if err != nil {
		irma.Logger.Warn(errors.WrapPrefix(err, "Failed to create log entry", 0).ErrorStack())
		session.client.reportError(err)
	}
	if err = session.client.storage.AddLogEntry(log); err != nil {
		irma.Logger.Warn(errors.WrapPrefix(err, "Failed to write log entry", 0).ErrorStack())
	}
	if session.Action == irma.ActionIssuing {
		session.client.handler.UpdateAttributes()
	}
	session.finish(false)

	if serverResponse != nil && serverResponse.NextSession != nil {
		session.next = session.client.newQrSession(serverResponse.NextSession, session.Handler)
		session.next.implicitDisclosure = session.choice.Attributes
	} else {
		session.Handler.Success(string(messageJson))
	}
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
			session.finish(false)
			session.Handler.KeyshareEnrollmentMissing(id)
			return false
		}
	}
	return true
}

func (session *session) checkAndUpdateConfiguration() error {
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
	if !session.IsExtern() && !session.checkKeyshareEnrollment() {
		return &irma.SessionError{ErrorType: irma.ErrorKeyshareUnenrolled}
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
		session.finish(false)
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

// finish the session, by sending a DELETE to the server if there is one, and restarting local
// background jobs. This function is idempotent, doing nothing when called a second time. It
// returns whether or not it did something.
func (session *session) finish(delete bool) bool {
	// In order to guarantee idempotency even if this function is simultaneously called by two threads
	// we need to synchronize here. We do this by having the session contain a channel (done), which
	// is initialized to buffer exactly 1 message, and is then closed. The first call to reach this if
	// will then read that message, whilst all further calls will see the closed channel and know
	// that no further work is needed.
	if _, ok := <-session.done; ok {
		session.client.sessions.remove(session.token)
		// Do actual delete in background, since that can take a while in some circumstances, and
		// precise moment of completion isn't relevant for frontend.
		go func() {
			if delete && session.IsInteractive() {
				_ = session.transport.Delete()
			}
			session.client.nonrevRepopulateCaches(session.request)
		}()
		return true
	}
	return false
}

func (session *session) fail(err *irma.SessionError) {
	if session.finish(true) && err.ErrorType != irma.ErrorKeyshareUnenrolled {
		irma.Logger.Warn("client session error: ", err.Error())
		// Don't use errors.Wrap() if err.Err == nil, otherwise we may get
		// https://yourbasic.org/golang/gotcha-why-nil-error-not-equal-nil/.
		// since errors.Wrap() returns an *errors.Error.
		if err.Err != nil {
			err.Err = errors.Wrap(err.Err, 0)
		}
		session.Handler.Failure(err)
	}
}

func (session *session) cancel() {
	if session.finish(true) {
		session.Handler.Cancelled()
	}
}

func (session *session) Dismiss() {
	if session.next != nil {
		session.next.Dismiss()
	} else {
		session.cancel()
	}
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
	session.finish(false)
	session.Handler.KeyshareEnrollmentIncomplete(manager)
}

func (session *session) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	session.finish(false)
	session.Handler.KeyshareEnrollmentDeleted(manager)
}

func (session *session) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	session.finish(false)
	session.Handler.KeyshareBlocked(manager, duration)
}

func (session *session) KeyshareError(manager *irma.SchemeManagerIdentifier, err error) {
	var serr *irma.SessionError
	var ok bool
	if serr, ok = err.(*irma.SessionError); !ok {
		serr = &irma.SessionError{ErrorType: irma.ErrorKeyshare, Err: err}
	}
	session.fail(serr)
}

func (session *session) KeysharePin() {
	session.Handler.StatusUpdate(session.Action, irma.ClientStatusConnected)
}

func (session *session) KeysharePinOK() {
	session.Handler.StatusUpdate(session.Action, irma.ClientStatusCommunicating)
}

func (s sessions) remove(token string) {
	last := s.sessions[token]
	delete(s.sessions, token)

	if last.Action == irma.ActionIssuing {
		for _, session := range s.sessions {
			session.requestPermission()
		}
	}

	if len(s.sessions) == 0 {
		s.client.StartJobs()
	}
}

func (s sessions) add(session *session) {
	session.token = common.NewSessionToken()
	s.sessions[session.token] = session
}
