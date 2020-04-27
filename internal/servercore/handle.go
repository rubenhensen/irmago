package servercore

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	ariesvc "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/privacybydesign/gabi"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

// This file contains the handler functions for the protocol messages, receiving and returning normally
// Go-typed messages here (JSON (un)marshalling is handled by the router).
// Maintaining the session state is done here, as well as checking whether the session is in the
// appropriate status before handling the request.

func (session *session) handleDelete() {
	if session.status.Finished() {
		return
	}
	session.markAlive()

	session.result = &server.SessionResult{Token: session.token, Status: server.StatusCancelled, Type: session.action}
	session.setStatus(server.StatusCancelled)
}

func (session *session) handleGetRequest(min, max *irma.ProtocolVersion, vc string)(irma.SessionRequest, *irma.RemoteError) {
	if session.status != server.StatusInitialized {
		return nil, server.RemoteError(server.ErrorUnexpectedRequest, "Session already started")
	}
	session.markAlive()

	logger := session.conf.Logger.WithFields(logrus.Fields{"session": session.token})

	// Handle legacy clients that do not support condiscon, by attempting to convert the condiscon
	// session request to the legacy session request format
	legacy, legacyErr := session.request.Legacy()
	session.legacyCompatible = legacyErr == nil
	if legacyErr != nil {
		logger.Info("Using condiscon: backwards compatibility with legacy IRMA apps is disabled")
	}

	var err error
	if session.version, err = session.chooseProtocolVersion(min, max); err != nil {
		return nil, session.fail(server.ErrorProtocolVersion, "")
	}
	logger.WithFields(logrus.Fields{"version": session.version.String()}).Debugf("Protocol version negotiated")
	session.request.Base().ProtocolVersion = session.version

	session.setStatus(server.StatusConnected)

	if session.version.Below(2, 5) {
		logger.Info("Returning legacy session format")
		legacy.Base().ProtocolVersion = session.version
		return legacy, nil
	}

	// in case of VC and issuing session, return
	ldcont := session.request.Disclosure().LDContext
	if vc == "yes" && ldcont == LDContextIssuanceRequest {
		// create VC session request
		session.request.Disclosure().LDContext = "TEST"
		return session.request, nil
	} else {
		return session.request, nil
	}
}

func (session *session) handleGetStatus() (server.Status, *irma.RemoteError) {
	return session.status, nil
}

func (session *session) handlePostSignature(signature *irma.SignedMessage) (*irma.ProofStatus, *irma.RemoteError) {
	if session.status != server.StatusConnected {
		return nil, server.RemoteError(server.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	var err error
	var rerr *irma.RemoteError
	session.result.Signature = signature
	session.result.Disclosed, session.result.ProofStatus, err = signature.Verify(
		session.conf.IrmaConfiguration, session.request.(*irma.SignatureRequest))
	if err == nil {
		session.setStatus(server.StatusDone)
	} else {
		if err == irma.ErrorMissingPublicKey {
			rerr = session.fail(server.ErrorUnknownPublicKey, err.Error())
		} else {
			rerr = session.fail(server.ErrorUnknown, err.Error())
		}
	}
	return &session.result.ProofStatus, rerr
}

func (session *session) handlePostDisclosure(disclosure irma.Disclosure) (*irma.ProofStatus, *irma.RemoteError) {
	if session.status != server.StatusConnected {
		return nil, server.RemoteError(server.ErrorUnexpectedRequest, "Session not yet started or already finished")
	}
	session.markAlive()

	var err error
	var rerr *irma.RemoteError
	session.result.Disclosed, session.result.ProofStatus, err = disclosure.Verify(
		session.conf.IrmaConfiguration, session.request.(*irma.DisclosureRequest))
	if err == nil {
		session.setStatus(server.StatusDone)
	} else {
		if err == irma.ErrorMissingPublicKey {
			rerr = session.fail(server.ErrorUnknownPublicKey, err.Error())
		} else {
			rerr = session.fail(server.ErrorUnknown, err.Error())
		}
	}
	return &session.result.ProofStatus, rerr
}

const (
	LDVerifiableCredential   = "https://www.w3.org/2018/credentials/v1"
	LDContextIssuanceRequest = "https://irma.app/ld/request/issuance/v2"
)

func (session *session) handlePostCommitments(commitments *irma.IssueCommitmentMessage) (interface{}, *irma.RemoteError) {
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

	session.setStatus(server.StatusDone)
	return sigs, nil
}

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

