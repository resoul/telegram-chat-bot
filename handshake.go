package wireauth

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	// Handshake v1 (DEPRECATED — see HANDSHAKE_SPEC.md "Security advisory").
	// The v1 signature covers only the two nonces, never the ECDH public
	// keys exchanged in stage 2, so it does not authenticate the key
	// exchange itself: an active network attacker can substitute either
	// ECDH public key in transit without invalidating the signature.
	// wireauth must run inside TLS when v1 is in use. v1 is accepted only
	// when a server is explicitly constructed with AllowLegacyV1().
	cmdStage1 = 1
	cmdStage2 = 2

	// Handshake v2 — signs the full transcript (both nonces and both ECDH
	// public keys) once, after stage 2, before the client trusts the
	// exchange. This is the default and only protocol unless legacy v1 is
	// explicitly enabled.
	cmdStage1V2 = 101
	cmdStage2V2 = 102

	nonceSize              = 16
	stage1ClientPacketSize = 4 + nonceSize
	stage1V2ServerRespSize = nonceSize // v2: nonce only, no signature yet

	stage2ClientPubKeySize = 65 // uncompressed P-256 public key
	stage2ClientPacketMin  = 4 + stage2ClientPubKeySize
	stage2V2ServerRespSize = stage2ClientPubKeySize + 256 // v2: pubkey + transcript signature
)

type Session struct {
	ClientToServerKey []byte
	ServerToClientKey []byte
	ServerNonce       []byte
}

type Server struct {
	privateKey    *rsa.PrivateKey
	timeout       time.Duration
	allowLegacyV1 bool
	validationErr error
}

type Option func(*Server)

func WithTimeout(d time.Duration) Option {
	return func(s *Server) { s.timeout = d }
}

// AllowLegacyV1 temporarily enables v1 for staged migrations. v1 does not
// authenticate the ECDH exchange, so it must only be used inside TLS.
func AllowLegacyV1() Option {
	return func(s *Server) { s.allowLegacyV1 = true }
}

func NewServer(privateKey *rsa.PrivateKey, opts ...Option) *Server {
	s := &Server{
		privateKey: privateKey,
		timeout:    10 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	if privateKey == nil || privateKey.N == nil || privateKey.N.BitLen() != 2048 {
		s.validationErr = ErrInvalidRSAKey
	} else if err := privateKey.Validate(); err != nil {
		s.validationErr = fmt.Errorf("%w: %v", ErrInvalidRSAKey, err)
	}
	return s
}

type deadlineSetter interface {
	SetReadDeadline(t time.Time) error
}

func (s *Server) Perform(ctx context.Context, conn MessageReadWriter) (*Session, error) {
	if s.validationErr != nil {
		return nil, s.validationErr
	}
	if ds, ok := conn.(deadlineSetter); ok {
		if err := ds.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
			return nil, fmt.Errorf("wireauth: failed to set read deadline: %w", err)
		}
		defer func() {
			_ = ds.SetReadDeadline(time.Time{})
		}()
	}

	packet, err := readHandshakePacket(conn, stage1ClientPacketSize, 0)
	if err != nil {
		return nil, err
	}

	switch binary.LittleEndian.Uint32(packet[:4]) {
	case cmdStage1V2:
		return s.performV2(conn, packet)
	case cmdStage1:
		if !s.allowLegacyV1 {
			return nil, fmt.Errorf("%w: enable AllowLegacyV1 to accept it", ErrLegacyHandshakeDisabled)
		}
		return s.performV1(conn, packet)
	default:
		return nil, ErrInvalidHandshakePacket
	}
}

// performV2 completes the v2 handshake and signs the full transcript,
// binding both ECDH public keys to the nonce exchange.
func (s *Server) performV2(conn MessageReadWriter, stage1Packet []byte) (*Session, error) {
	clientNonce := stage1Packet[4 : 4+nonceSize]
	serverNonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	if err := writeHandshakeMessage(conn, serverNonce); err != nil {
		return nil, err
	}

	clientPubBytes, err := readClientPublicKey(conn, cmdStage2V2)
	if err != nil {
		return nil, err
	}
	sharedSecret, serverPubBytes, err := performECDH(clientPubBytes)
	if err != nil {
		return nil, err
	}

	signature, err := s.sign(clientNonce, serverNonce, clientPubBytes, serverPubBytes)
	if err != nil {
		return nil, err
	}
	if err := writeHandshakeMessage(conn, joinBytes(serverPubBytes, signature)); err != nil {
		return nil, err
	}

	clientToServer, serverToClient := deriveV2DirectionalKeys(sharedSecret, clientNonce, serverNonce)
	return &Session{ClientToServerKey: clientToServer, ServerToClientKey: serverToClient, ServerNonce: serverNonce}, nil
}

// performV1 completes the legacy handshake, which does not authenticate ECDH keys.
func (s *Server) performV1(conn MessageReadWriter, stage1Packet []byte) (*Session, error) {
	clientNonce := stage1Packet[4 : 4+nonceSize]
	serverNonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	signature, err := s.sign(clientNonce, serverNonce)
	if err != nil {
		return nil, err
	}
	if err := writeHandshakeMessage(conn, joinBytes(serverNonce, signature)); err != nil {
		return nil, err
	}

	clientPubBytes, err := readClientPublicKey(conn, cmdStage2)
	if err != nil {
		return nil, err
	}
	sharedSecret, serverPubBytes, err := performECDH(clientPubBytes)
	if err != nil {
		return nil, err
	}

	aesKey := sha256.Sum256(joinBytes(sharedSecret, clientNonce, serverNonce))
	if err := writeHandshakeMessage(conn, serverPubBytes); err != nil {
		return nil, err
	}
	return &Session{ClientToServerKey: aesKey[:], ServerToClientKey: aesKey[:], ServerNonce: serverNonce}, nil
}

func generateNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("wireauth: failed to generate server nonce: %w", err)
	}
	return nonce, nil
}

func readHandshakePacket(conn MessageReadWriter, expectedSize int, expectedCommand uint32) ([]byte, error) {
	msgType, packet, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeReadFailed, err)
	}
	if msgType != BinaryMessageType || len(packet) != expectedSize || (expectedCommand != 0 && binary.LittleEndian.Uint32(packet[:4]) != expectedCommand) {
		return nil, ErrInvalidHandshakePacket
	}
	return packet, nil
}

func readClientPublicKey(conn MessageReadWriter, command uint32) ([]byte, error) {
	packet, err := readHandshakePacket(conn, stage2ClientPacketMin, command)
	if err != nil {
		return nil, err
	}
	return packet[4:], nil
}

func performECDH(clientPubBytes []byte) ([]byte, []byte, error) {
	curve := ecdh.P256()
	serverPrivKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("wireauth: failed to generate server ECDH key: %w", err)
	}
	clientPubKey, err := curve.NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidClientPubKey, err)
	}
	sharedSecret, err := serverPrivKey.ECDH(clientPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("wireauth: ECDH failed: %w", err)
	}
	return sharedSecret, serverPrivKey.PublicKey().Bytes(), nil
}

func (s *Server) sign(parts ...[]byte) ([]byte, error) {
	hash := sha256.Sum256(joinBytes(parts...))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureFailed, err)
	}
	return signature, nil
}

func writeHandshakeMessage(conn MessageReadWriter, payload []byte) error {
	if err := conn.WriteMessage(BinaryMessageType, payload); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeWriteFailed, err)
	}
	return nil
}

func joinBytes(parts ...[]byte) []byte {
	length := 0
	for _, part := range parts {
		length += len(part)
	}
	joined := make([]byte, 0, length)
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}
