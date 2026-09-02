package wireauth

import (
	"crypto/hmac"
	"crypto/sha256"
)

var (
	v2ClientToServerInfo = []byte("wireauth/v2/client-to-server")
	v2ServerToClientInfo = []byte("wireauth/v2/server-to-client")
)

// deriveV2DirectionalKeys derives independent keys for each traffic direction.
// The salt binds the derivation to this handshake's two fresh nonces.
func deriveV2DirectionalKeys(sharedSecret, clientNonce, serverNonce []byte) (clientToServer, serverToClient []byte) {
	salt := make([]byte, 0, len(clientNonce)+len(serverNonce))
	salt = append(salt, clientNonce...)
	salt = append(salt, serverNonce...)

	extract := hmac.New(sha256.New, salt)
	extract.Write(sharedSecret)
	prk := extract.Sum(nil)

	return hkdfExpandSHA256(prk, v2ClientToServerInfo, 32),
		hkdfExpandSHA256(prk, v2ServerToClientInfo, 32)
}

func hkdfExpandSHA256(prk, info []byte, length int) []byte {
	mac := hmac.New(sha256.New, prk)
	mac.Write(info)
	mac.Write([]byte{1})
	return mac.Sum(nil)[:length]
}
