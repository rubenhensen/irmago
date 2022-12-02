# to do
1. Implementeer andere manier van aanleveren linkjes/qrcodes
1. Bouw test suite 
1. Herken een vc request vanuit de app.
2. Genereer een vc ipv een een irma
3. public key download
4. issuer info download
5. klaar

# public key

# handige commandos
vc-test-suite `npm --prefix ..\..\vc-test-suite\ test -- --timeout 10000`
vc-test-suite build `go build -a -ldflags '-extldflags "-static"' -o "C:\Users\Ruben\sidn\vc-test-suite\irma.exe" ./irma`

# implement endpoints vc-api
<!-- Issuing:
GET /credentials	Gets list of credentials or verifiable credentials
GET /credentials/{id}	Gets a credential or verifiable credential by ID
DELETE /credentials/{id}	Deletes a credential or verifiable credential by ID
POST /credentials/issue	Issues a credential and returns it in the response body.
POST /credentials/status	Updates the status of an issued credential -->
<!-- Verifying:
| Endpoint                   | Description                                                                                                    |
|----------------------------|----------------------------------------------------------------------------------------------------------------|
| POST /credentials/verify   | Verifies a verifiableCredential and returns a verificationResult in the response body.                         |
| POST /presentations/verify | Verifies a Presentation with or without proofs attached and returns a verificationResult in the response body. | -->
<!-- Presentation
| Endpoint                                       | Description                                                |
|------------------------------------------------|------------------------------------------------------------|
| POST /credentials/derive                       | Derives a credential and returns it in the response body.  |
| POST /presentations/prove                      | Proves a presentation and returns it in the response body. |
| GET /presentations                             | Gets list of presentations or verifiable presentations     |
| GET /presentations/{id}                        | Gets a presentation or verifiable presentation by ID       |
| DELETE /presentations/{id}                     | Deletes a presentation or verifiable presentation by ID    |
| POST /exchanges/                               | Error: API Endpoint not defined - /exchanges/              |
| POST /exchanges/{exchange-id}                  | Initiates an exchange of information.                      |
| POST /exchanges/{exchange-id}/{transaction-id} | Receives information related to an existing exchange.      | -->

https://w3c-ccg.github.io/vp-request-spec/
implement vc request spec?
Waarschijnlijk niet. Document is niet duidelijk. Niet in W3C track. Midden in ontwikkeling. Irma heeft al een eigen manier.

{"u":"http://172.16.0.34:48680/session/JhklJeqezH7PPYVKfYvH","irmaqr":"disclosing"}
# implement irma commands
expand issue command to do internal check