# internal/servercore -> server/irmaserver
internal/servercore/api.go -> server/irmaserver/api.go
internal/servercore/handle.go -> server/irmaserver/handle.go
internal/servercore/helpers.go -> server/irmaserver/helpers.go
internal/servercore/sessions.go -> server/irmaserver/sessions.go
internal/servercore/main.go -> deleted

## api.go
Change: Add GetConfig func
```go
func (s *Server) GetConfig() *server.Configuration {
	return s.conf
}
```
Merge: Added GetConfig() to server/irmaserver/api.go

Change: updated regex with 'presentation'
```go
func ParsePath(path string) (string, string, error) {
	pattern := regexp.MustCompile("(\\w+)/?(|presentation|commitments|proofs|status|statusevents)$")
    ...
```
Merge: No ParsePath found, discarded


Change: Add VC to handleProtocolMessage
```go
func (s *Server) handleProtocolMessage(
	path string,
	method string,
	headers map[string][]string,
	message []byte,
) (status int, output []byte, result *server.SessionResult) {
    ...
    	h := http.Header(headers)
	min := &irma.ProtocolVersion{}
	if err := json.Unmarshal([]byte(h.Get(irma.MinVersionHeader)), min); err != nil {
	}

	// Get VC Header
	// User-Agent should be used in future production read version
	vcHeader := h.Get(irma.VCHeader)

	// possible to do without session?
    ...
    	// Route to handler
	switch len(noun) {
	case 0:
		if method == http.MethodDelete {
			session.handleDelete()
			status = http.StatusOK
			return
		}
		if method == http.MethodGet {
			h := http.Header(headers)
			min := &irma.ProtocolVersion{}
			max := &irma.ProtocolVersion{}
			if err := json.Unmarshal([]byte(h.Get(irma.MinVersionHeader)), min); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, err.Error()))
				return
			}
			if err := json.Unmarshal([]byte(h.Get(irma.MaxVersionHeader)), max); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, err.Error()))
				return
			}
			status, output = server.JsonResponse(session.handleGetRequest(min, max, vcHeader)) // added vcHeader
			return
		}
		status, output = server.JsonResponse(nil, session.fail(server.ErrorInvalidRequest, ""))
		return

    ...
    	if noun == "commitments" && session.action == irma.ActionIssuing {
			commitments := &irma.IssueCommitmentMessage{}

            // VC from here
			vc := &irma.VerifiableCredential{}

			// if message conforms to VC format, map ProofMsg to commitments object
			// TODO: Refactor to just check if commitment is VC message or not
			//if vcHeader == "yes" {
					if err := irma.UnmarshalValidate(message, vc); err != nil {

						// if message is no VC message, use legacy IRMA processing
						if err := irma.UnmarshalValidate(message, commitments); err != nil {
							status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, ""))
							return
						} else {
							status, output = server.JsonResponse(session.handlePostCommitments(commitments))
							return
						}

					} else {

						s.conf.Logger.WithField("clientToken", token).Info("Valid VC detected")

						vcProof, _ := json.Marshal(vc.Proof.ProofMsg)
						if err := irma.UnmarshalValidate(vcProof, commitments); err != nil {
							status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, ""))
							return
						} else {
							status, output = server.JsonResponse(session.handlePostCommitmentsVC(commitments))
							return
						}

					}
		}
        
		if noun == "proofs" && vcHeader != "yes" && session.action == irma.ActionDisclosing {
            // To here

			disclosure := irma.Disclosure{}
			if err := irma.UnmarshalValidate(message, &disclosure); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, ""))
				return
			}

            // From here
			status, output = server.JsonResponse(session.handlePostDisclosure(disclosure))
			return
		}
		if noun == "proofs" && vcHeader == "yes" && session.action == irma.ActionDisclosing {

			disclosure := irma.Disclosure{}
			verifiablePresentation := irma.VerifiablePresentation{}
			if err := irma.UnmarshalValidate(message, &verifiablePresentation); err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, ""))
				return
			}

			s.conf.Logger.WithField("clientToken", token).Info("Valid verifiable presentation detected")

			proofByte, err := json.Marshal(verifiablePresentation.Proof.ProofMsg)
			err = json.Unmarshal(proofByte, &disclosure)
			if err != nil {
				status, output = server.JsonResponse(nil, session.fail(server.ErrorMalformedInput, ""))
				return
			}
            // to here
```
Merge: found similar code in handle.go, TODO: refactor into handle.go and api.go
```go
// server/irmaserver/handle.go
func (s *Server) handleSessionProofs(w http.ResponseWriter, r *http.Request) {
	bts, err := ioutil.ReadAll(r.Body)
	if err != nil {
		server.WriteError(w, server.ErrorMalformedInput, err.Error())
		return
	}
	session := r.Context().Value("session").(*session)
	var res *irma.ServerSessionResponse
	var rerr *irma.RemoteError
	switch session.Action {
	case irma.ActionDisclosing:
    // this part is almost the same
		disclosure := &irma.Disclosure{}
		if err := irma.UnmarshalValidate(bts, disclosure); err != nil {
			server.WriteError(w, server.ErrorMalformedInput, err.Error())
			return
		}
		res, rerr = session.handlePostDisclosure(disclosure)
```

```go
// server/irmaserver/api.go
func (s *Server) HandlerFunc() http.HandlerFunc {
	if s.router != nil {
		return s.router.ServeHTTP
	}

	r := chi.NewRouter()
	s.router = r

	opts := server.LogOptions{Response: true, Headers: true, From: false, EncodeBinary: true}
	r.Use(server.LogMiddleware("client", opts))

	r.Use(server.SizeLimitMiddleware)
	r.Use(server.TimeoutMiddleware([]string{"/statusevents", "/updateevents"}, server.WriteTimeout))

	notfound := &irma.RemoteError{Status: 404, ErrorName: string(server.ErrorInvalidRequest.Type)}
	notallowed := &irma.RemoteError{Status: 405, ErrorName: string(server.ErrorInvalidRequest.Type)}
	r.NotFound(errorWriter(notfound, server.WriteResponse))
	r.MethodNotAllowed(errorWriter(notallowed, server.WriteResponse))

	r.Route("/session/{clientToken}", func(r chi.Router) {
		r.Use(s.sessionMiddleware)
		r.Delete("/", s.handleSessionDelete)
		r.Get("/status", s.handleSessionStatus)
		r.Get("/statusevents", s.handleSessionStatusEvents)
		r.Route("/frontend", func(r chi.Router) {
			r.Use(s.frontendMiddleware)
			r.Get("/status", s.handleFrontendStatus)
			r.Get("/statusevents", s.handleFrontendStatusEvents)
			r.Post("/options", s.handleFrontendOptionsPost)
			r.Post("/pairingcompleted", s.handleFrontendPairingCompleted)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.cacheMiddleware)
			r.Get("/", s.handleSessionGet)
			r.Group(func(r chi.Router) {
				r.Use(s.pairingMiddleware)
				r.Get("/request", s.handleSessionGetRequest)
				r.Post("/commitments", s.handleSessionCommitments)
				r.Post("/proofs", s.handleSessionProofs)
			})
		})
	})
```


## handle.go
Change: import ariesvc
```go
ariesvc "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
```
Merge: add import

Change: add consts
```go
const (
	LDVerifiableCredential   = "https://www.w3.org/2018/credentials/v1"
	LDContextIssuanceRequest = "https://irma.app/ld/request/issuance/v2"
)
```
Merge: add consts to handle.go

Change: add handlePostCommitmentsVC()
```go
func (session *session) handlePostCommitmentsVC(commitments *irma.IssueCommitmentMessage) (interface{}, *irma.RemoteError) {
	if session.status != server.StatusConnected {
		return nil, server.RemoteError(server.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	request := session.request.(*irma.IssuanceRequest)

	byteR, _ := json.Marshal(request)
	fields := logrus.Fields{}
	fields["message"] = string(byteR)
	server.Logger.WithFields(fields).Tracef("=> Request")

	discloseCount := len(commitments.Proofs) - len(request.Credentials)
	if discloseCount < 0 {
		return nil, session.fail(server.ErrorMalformedInput, "Received insufficient proofs")
	}

	// Compute list of public keys against which to verify the received proofs
	disclosureproofs := irma.ProofList(commitments.Proofs[:discloseCount])
	pubkeys, err := disclosureproofs.ExtractPublicKeys(session.conf.IrmaConfiguration)
	if err != nil {
		return nil, session.fail(server.ErrorMalformedInput, err.Error())
	}
	for _, cred := range request.Credentials {
		iss := cred.CredentialTypeID.IssuerIdentifier()
		pubkey, _ := session.conf.IrmaConfiguration.PublicKey(iss, cred.KeyCounter) // No error, already checked earlier
		pubkeys = append(pubkeys, pubkey)
	}

	// Verify and merge keyshare server proofs, if any
	for i, proof := range commitments.Proofs {
		pubkey := pubkeys[i]
		schemeid := irma.NewIssuerIdentifier(pubkey.Issuer).SchemeManagerIdentifier()
		if session.conf.IrmaConfiguration.SchemeManagers[schemeid].Distributed() {
			proofP, err := session.getProofP(commitments, schemeid)
			if err != nil {
				return nil, session.fail(server.ErrorKeyshareProofMissing, err.Error())
			}
			proof.MergeProofP(proofP, pubkey)
		}
	}

	// Verify all proofs and check disclosed attributes, if any, against request
	session.result.Disclosed, session.result.ProofStatus, err = commitments.Disclosure().VerifyAgainstDisjunctions(
		session.conf.IrmaConfiguration, request.Disclose, request.GetContext(), request.GetNonce(nil), pubkeys, false)
	if err != nil {
		if err == irma.ErrorMissingPublicKey {
			return nil, session.fail(server.ErrorUnknownPublicKey, "")
		} else {
			return nil, session.fail(server.ErrorUnknown, "")
		}
	}
	if session.result.ProofStatus == irma.ProofStatusExpired {
		return nil, session.fail(server.ErrorAttributesExpired, "")
	}
	if session.result.ProofStatus != irma.ProofStatusValid {
		return nil, session.fail(server.ErrorInvalidProofs, "")
	}

	// Compute CL signatures
	var sigs []*gabi.IssueSignatureMessage
	for i, cred := range request.Credentials {
		id := cred.CredentialTypeID.IssuerIdentifier()
		pk, _ := session.conf.IrmaConfiguration.PublicKey(id, cred.KeyCounter)
		sk, _ := session.conf.PrivateKey(id)
		issuer := gabi.NewIssuer(sk, pk, one)
		proof, ok := commitments.Proofs[i+discloseCount].(*gabi.ProofU)
		if !ok {
			return nil, session.fail(server.ErrorMalformedInput, "Received invalid issuance commitment")
		}
		attributes, err := cred.AttributeList(session.conf.IrmaConfiguration, 0x03)
		if err != nil {
			return nil, session.fail(server.ErrorIssuanceFailed, err.Error())
		}
		sig, err := issuer.IssueSignature(proof.U, attributes.Ints, commitments.Nonce2)
		if err != nil {
			return nil, session.fail(server.ErrorIssuanceFailed, err.Error())
		}
		sigs = append(sigs, sig)
	}

	irmaVCServerURL := session.conf.IrmaConfiguration.SchemeManagers[request.Credentials[0].CredentialTypeID.IssuerIdentifier().SchemeManagerIdentifier()].TypeServerURL
	externalIP, _ := irma.ExternalIP()
	if len(irmaVCServerURL) == 0 {
		irmaVCServerURL =  "http://" + externalIP + ":8089/"
	}

	vcObj := irma.VerifiableCredential{}

	// context
	vcObj.LDContext = [2]string{LDVerifiableCredential, LDContextIssuanceRequest}

	// type
	vcObj.Type = make([]string, 1)
	vcObj.Type[0] = "VerifiableCredential"

	// issuer
	issuerID := request.Credentials[0].CredentialTypeID.IssuerIdentifier()
	vcObj.Issuer = issuerID.String()

	// public key counter
	pkIndices, _ := session.conf.IrmaConfiguration.PublicKeyIndices(issuerID)
	highest := -1
	for current := range pkIndices {
		if current > highest {
			highest = current
		}
	}
	highestStr := strconv.Itoa(highest)

	// issuer URI
	vcObj.Issuer = irmaVCServerURL + "issuer/" + strings.Replace(vcObj.Issuer, ".", "/", -1) + "/" + highestStr

	// issuance date
	layout := "2006-01-02T15:04:05Z"
	vcObj.IssuanceDate = time.Now().Format(layout)

	// The value of the credentialSubject property is defined as a set of objects
	// that contain one or more properties that are each related to a subject of the VC.
	for _, cred := range request.Credentials {
		// for each credential type one schema
		vcObj.Schema = append(vcObj.Schema, irma.VCSchema{Identifier: irmaVCServerURL + "schema/" + strings.Replace(cred.CredentialTypeID.String(), ".", "/", -1), Type: "JsonSchemaValidator2018"})

		// types
		vcObj.Type = append(vcObj.Type, cred.CredentialTypeID.Name())
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
		vcObj.CredentialSubjects = append(vcObj.CredentialSubjects, obj)
	}

	vcObj.Proof.Type = "IdemixZKP"
	vcObj.Proof.Created = time.Now().Format(time.RFC3339)
	vcObj.Proof.ProofMsg = sigs

	byteArray, err := json.Marshal(vcObj)
	if err != nil {
		server.Logger.Errorf("=> VC marshalling issue")
	}

	unused, _, err := ariesvc.NewCredential(byteArray)
	if err != nil {
		fields["message"] = err.Error()
		server.Logger.WithFields(fields).Tracef("=> Invalid Aries VC")
	} else {
		byteArray, err = json.Marshal(unused)
		fields["message"] = string(byteArray)
		//server.Logger.WithFields(fields).Tracef("=> Valid Aries VC")
	}

	session.setStatus(server.StatusDone)
	return vcObj, nil
}
```
Merge: Add handlePostCommitmentsVC()


Change: Added some logging logic to handlePostCommitment and return extra interface
```go
func (session *session) handlePostCommitments(commitments *irma.IssueCommitmentMessage) (interface{}, *irma.RemoteError) {
	if session.status != server.StatusConnected {
		return nil, server.RemoteError(server.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	request := session.request.(*irma.IssuanceRequest)
    // from here
	byteR, _ := json.Marshal(request)
	fields := logrus.Fields{}
	fields["message"] = string(byteR)
	server.Logger.WithFields(fields).Tracef("=> Request")
    // to here
```
Merge: Discard for now, could be added to irmaserver/handle.go

Change: Add a VC case to handleGetRequest() and add vc param
```go
func (session *session) handleGetRequest(min, max *irma.ProtocolVersion, vc string)(irma.SessionRequest, *irma.RemoteError) {
    ...
	// in case of VC and issuing session, return
	ldcont := session.request.Disclosure().LDContext
	if vc == "yes" && ldcont == LDContextIssuanceRequest {
		// create VC session request
		session.request.Disclosure().LDContext = "TEST"
		return session.request, nil
	} else {
		return session.request, nil
	}
    ...
```
Merge: found in irmaserver/handle.go handleGetClientRequest(), added changes

# internal/fs -> server/common
Renamed

# internal/disable_sigpipe
No change TODO: check if true

# internal/keysharecore
No change

# internal/sessiontest
## server_test.go -> helper_servers_test.go
Change: Added false (isMetaDataServer)
```go
func StartRequestorServer(configuration *requestorserver.Configuration) {
	go func() {
		var err error
		if requestorServer, err = requestorserver.New(configuration); err != nil {
			panic(err)
		}
		if err = requestorServer.Start(configuration, false); err != nil { // this false
			panic("Starting server failed: " + err.Error())
		}
	}()
	time.Sleep(100 * time.Millisecond) // Give server time to start
}
```
Merge: moved to helper_servers_test.go, added false

## requestor_test.go -> helper_requestor_test.go
Moved

## main_test.go -> helper_main_test.go
Moved

# irma
## root.go
Change: about cmd "dan version"
Merge: discarded change


# irmaclient
## client.go
Change: Add verifiableCredentials var to client struct
```go
type Client struct {
	// Stuff we manage on disk
	secretkey        *secretKey
	attributes       map[irma.CredentialTypeIdentifier][]*irma.AttributeList
...
	// VC
	verifiableCredentials []irma.VerifiableCredential
}
```
Merge: Add verifiableCredentials var to client struct

## logs.go
Change: added protocolversion
```go
Version *irma.ProtocolVersion `json:",omitempty"` 
```
Merge: Remove protocolversion, it is just old irma, nothing to do with vc


## session.go
Change: Add presentation and credential type
```go
	// Issuance sessions
	IssueCommitment *irma.IssueCommitmentMessage 	`json:",omitempty"`

	// All session types
	ServerName *irma.RequestorInfo   `json:",omitempty"`
	Version    *irma.ProtocolVersion `json:",omitempty"`
	Disclosure *irma.Disclosure      `json:",omitempty"`
	Request    json.RawMessage       	`json:",omitempty"`
	Presentation    irma.VerifiablePresentation	`json:",omitempty"`
	Credential 		*irma.VerifiableCredential		`json:",omitempty"` // Message that started the session
	request    irma.SessionRequest   // cached parsed version of Request; get with LogEntry.SessionRequest()
}
```
Merge: Add presentation and credential type


Change: Different error handling and added a sovrin qr
```go
	qr := &irma.Qr{}
	if err := json.Unmarshal(bts, qr); err == nil && qr.IsQr() {
		if err = qr.Validate(); err != nil {
			handler.Failure(&irma.SessionError{ErrorType: irma.ErrorInvalidRequest, Err: err})
			return nil
		}
		return client.newQrSession(qr, handler, irma.IssueVC)
	}

	// Example: {"url":"http://192.168.2.100:8088/irma/f6JOn5NZqheTspDFISzW","action":"disclosing", "system":"sovrin"}
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
```
Merge: updated to the new error handling, added sovrin qr with new error handling

Change: Old and new way of newQrSession

```go
func (client *Client) newQrSession(qr *irma.Qr, handler Handler) *session {
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
```
Merge: Changed to new way TODO: old way added 'extern' which is now not implemented in the new way. this might cause issues

Change: Add vp func
```go
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
```
Merge: add vp func

Change: if isInteractive AND disclosing and message type equals VP, add vcheader
```go
if session.IsInteractive() {
		if err = session.transport.Post(path, &serverResponse, ourResponse); err != nil {
			if message.(type) == irma.VerifiablePresentation {
				session.transport.SetHeader(irma.VCHeader, "yes")
			}
			session.fail(err.(*irma.SessionError))
			return
		}
```
Merge: Added header

Change: if issuing and VC then add VC header to session and use constructVerifiableCredentials() 
```go
	if session.IsInteractive() {
		if err = session.transport.Post(path, &serverResponse, ourResponse); err != nil {
			if message.(type) == irma.VerifiablePresentation {
				session.transport.SetHeader(irma.VCHeader, "yes")
			}
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
        // added this
		if session.Action == irma.ActionIssuing && irma.IssueVC {
			if err = session.client.ConstructVerifiableCredentials(serverResponse.IssueSignatures, session.request.(*irma.IssuanceRequest), session.builders); err != nil {
				session.fail(&irma.SessionError{ErrorType: irma.ErrorCrypto, Err: err})
				return
			}
		}
	}

```
Merge: Add constructVerifiable()


## storage.go
Change: add vcFile to const
```go
// Bucketnames bbolt
const (
	userdataBucket  = "userdata"     // Key/value: specified below
	skKey           = "sk"           // Value: *secretKey
	credTypeKeysKey = "credTypeKeys" // Value: map[irma.CredentialTypeIdentifier][]byte
	preferencesKey  = "preferences"  // Value: Preferences
	updatesKey      = "updates"      // Value: []update
	kssKey          = "kss"          // Value: map[irma.SchemeManagerIdentifier]*keyshareServer

	attributesBucket = "attrs" // Key: []byte, value: []*irma.AttributeList
	logsBucket       = "logs"  // Key: (auto-increment index), value: *LogEntry
	signaturesBucket = "sigs"  // Key: credential.attrs.Hash, value: *gabi.CLSignature
    vcFile           = "vc"
)
```
Merge: Add vcFile to const


# server/requestorserver
## conf.go
Change: Add metadata port
```go
	// Port to listen at for type server
	MetadataPort int `json:"metadataport" mapstructure:"metadataport"`
```
Merge: Metadata port



