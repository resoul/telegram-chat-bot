package wireauth

import "errors"

type MessageReadWriter interface {
	ReadMessage() (messageType int, payload []byte, err error)
	WriteMessage(messageType int, payload []byte) error
}

const BinaryMessageType = 2

var (
	ErrHandshakeReadFailed     = errors.New("wireauth: failed to read handshake message")
	ErrHandshakeWriteFailed    = errors.New("wireauth: failed to write handshake message")
	ErrInvalidRSAKey           = errors.New("wireauth: invalid RSA key")
	ErrInvalidClientPubKey     = errors.New("wireauth: invalid client ECDH public key")
	ErrSignatureFailed         = errors.New("wireauth: RSA signature generation failed")
	ErrPacketTooShort          = errors.New("wireauth: packet too short")
	ErrDecryptionFailed        = errors.New("wireauth: AEAD decryption failed")
	ErrLegacyHandshakeDisabled = errors.New("wireauth: legacy v1 handshake rejected")
	ErrInvalidHandshakePacket  = errors.New("wireauth: invalid handshake packet")
)
