package irmaclient

import (
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
)

// keyshareEnrollmentHandler handles the keyshare attribute issuance session
// after registering to a new keyshare server.
type keyshareEnrollmentHandler struct {
	pin    string
	client *Client
	kss    *keyshareServer
}

// Force keyshareEnrollmentHandler to implement the Handler interface
var _ Handler = (*keyshareEnrollmentHandler)(nil)

// Session handlers in the order they are called

func (h *keyshareEnrollmentHandler) RequestIssuancePermission(request *irma.IssuanceRequest, satisfiable bool, candidates [][]DisclosureCandidates, ServerName *irma.RequestorInfo, callback PermissionHandler) {
	// Fetch the username from the credential request and save it along with the scheme manager
	for _, attr := range request.Credentials[0].Attributes {
		h.kss.Username = attr
		break
	}

	// Do the issuance
	callback(true, nil)
}

func (h *keyshareEnrollmentHandler) RequestPin(remainingAttempts int, callback PinHandler) {
	if remainingAttempts == -1 { // -1 signifies that this is the first attempt
		callback(true, h.pin)
	} else {
		h.fail(errors.New("PIN incorrect"))
	}
}

func (h *keyshareEnrollmentHandler) Success(result string) {
	_ = h.client.storage.StoreKeyshareServers(h.client.keyshareServers) // TODO handle err?
	h.client.handler.EnrollmentSuccess(h.kss.SchemeManagerIdentifier)
}

func (h *keyshareEnrollmentHandler) Failure(err *irma.SessionError) {
	h.fail(err)
}

// fail is a helper to ensure the kss is removed from the client in case of any problem
func (h *keyshareEnrollmentHandler) fail(err error) {
	delete(h.client.keyshareServers, h.kss.SchemeManagerIdentifier)
	h.client.handler.EnrollmentFailure(h.kss.SchemeManagerIdentifier, err)
}

// Not interested, ingore
func (h *keyshareEnrollmentHandler) StatusUpdate(action irma.Action, status irma.ClientStatus) {}

// The methods below should never be called, so we let each of them fail the session
func (h *keyshareEnrollmentHandler) RequestVerificationPermission(request *irma.DisclosureRequest, satisfiable bool, candidates [][]DisclosureCandidates, ServerName *irma.RequestorInfo, callback PermissionHandler) {
	callback(false, nil)
}
func (h *keyshareEnrollmentHandler) RequestSignaturePermission(request *irma.SignatureRequest, satisfiable bool, candidates [][]DisclosureCandidates, ServerName *irma.RequestorInfo, callback PermissionHandler) {
	callback(false, nil)
}
func (h *keyshareEnrollmentHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	callback(false)
}
func (h *keyshareEnrollmentHandler) Cancelled() {
	h.fail(errors.New("Keyshare enrollment session unexpectedly cancelled"))
}
func (h *keyshareEnrollmentHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	h.fail(errors.New("Keyshare enrollment failed: blocked"))
}
func (h *keyshareEnrollmentHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("Keyshare enrollment failed: registration incomplete"))
}
func (h *keyshareEnrollmentHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("Keyshare enrollment failed: not enrolled"))
}
func (h *keyshareEnrollmentHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("Keyshare enrollment failed: unenrolled"))
}
func (h *keyshareEnrollmentHandler) ClientReturnURLSet(clientReturnURL string) {
	h.fail(errors.New("Keyshare enrollment session unexpectedly found an external return url"))
}
func (h *keyshareEnrollmentHandler) PairingRequired(pairingCode string) {
	h.fail(errors.New("Keyshare enrollment session failed: device pairing required"))
}
