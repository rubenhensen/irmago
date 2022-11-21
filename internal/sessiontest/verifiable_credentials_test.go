package sessiontest

import (
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/stretchr/testify/require"
)

func TestVerifiableCredentials(t *testing.T) {
	t.Run("DisclosureSession", apply(testVcDisclosureSession, RequestorVCServerConfiguration()))
}

func testVcDisclosureSession(t *testing.T, conf interface{}, opts ...option) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := getDisclosureRequest(id)
	for _, opt := range []option{0, optionRetryPost} {
		serverResult := doSession(t, request, nil, nil, nil, nil, conf, append(opts, opt)...)
		logger.WithField("serverResult", serverResult).Info("dsfjk")
		require.Nil(t, serverResult.Err)
		require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
		require.Len(t, serverResult.Disclosed, 1)
		require.Equal(t, id, serverResult.Disclosed[0][0].Identifier)
		require.Equal(t, "456", serverResult.Disclosed[0][0].Value["en"])
	}
}

func RequestorVCServerConfiguration() *requestorserver.Configuration {
	irmaServerConf := IrmaServerConfiguration()
	irmaServerConf.URL = requestorServerURL + "/irma"
	return &requestorserver.Configuration{
		Configuration:                  irmaServerConf,
		DisableRequestorAuthentication: true,
		ListenAddress:                  "localhost",
		Port:                           requestorServerPort,
		MaxRequestAge:                  3,
		VerifiableCredential:           true,
		Permissions: requestorserver.Permissions{
			Disclosing: []string{"*"},
			Signing:    []string{"*"},
			Issuing:    []string{"*"},
		},
	}
}

// func verfiableCredentialsRequestorConfigDecorator(mr string, cert string, certfile string, fn func() *requestorserver.Configuration) func() *requestorserver.Configuration {
// 	return func() *requestorserver.Configuration {
// 		c := fn()
// 		verifiableCredentialsConfigDecorator(mr, cert, certfile, func() *server.Configuration { return c.Configuration })()
// 		return c
// 	}
// }

// func verifiableCredentialsConfigDecorator(mr string, cert string, certfile string, fn func() *server.Configuration) func() *server.Configuration {
// 	return func() *server.Configuration {
// 		mr.FlushAll() // Flush Redis memory between different runs of the IRMA server to prevent side effects.
// 		c := fn()
// 		c.StoreType = "redis"
// 		c.RedisSettings = &server.RedisSettings{}
// 		c.RedisSettings.Addr = mr.Host() + ":" + mr.Port()

// 		if cert != "" {
// 			c.RedisSettings.TLSCertificate = cert
// 		} else if certfile != "" {
// 			c.RedisSettings.TLSCertificateFile = certfile
// 		} else {
// 			c.RedisSettings.DisableTLS = true
// 		}
// 		return c
// 	}
// }
