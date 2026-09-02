package wireauth

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"os"
	"testing"
)

type fakeConn struct {
	toServer   chan []byte
	fromServer chan []byte
}

func newFakeConnPair() (server, client *fakeConn) {
	a := make(chan []byte, 4)
	b := make(chan []byte, 4)
	server = &fakeConn{toServer: a, fromServer: b}
	client = &fakeConn{toServer: a, fromServer: b}
	return
}

func (c *fakeConn) ReadMessage() (int, []byte, error) {
	msg := <-c.toServer
	return BinaryMessageType, msg, nil
}
func (c *fakeConn) WriteMessage(_ int, payload []byte) error {
	c.fromServer <- payload
	return nil
}

type clientConn struct{ *fakeConn }

func (c clientConn) ReadMessage() (int, []byte, error) {
	msg := <-c.fromServer
	return BinaryMessageType, msg, nil
}
func (c clientConn) WriteMessage(_ int, payload []byte) error {
	c.toServer <- payload
	return nil
}

func mustGenRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return key
}

// TestHandshakeV1_EndToEnd preserves legacy compatibility during migration.
func TestHandshakeV1_EndToEnd(t *testing.T) {
	priv := mustGenRSA(t)
	srv := NewServer(priv, AllowLegacyV1())

	serverSide, clientSideRaw := newFakeConnPair()
	clientSide := clientConn{clientSideRaw}

	serverSessionCh := make(chan *Session, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		sess, err := srv.Perform(context.Background(), serverSide)
		serverSessionCh <- sess
		serverErrCh <- err
	}()

	clientNonce := make([]byte, 16)
	if _, err := rand.Read(clientNonce); err != nil {
		t.Fatal(err)
	}
	stage1Packet := make([]byte, 4+16)
	binary.LittleEndian.PutUint32(stage1Packet[0:4], 1)
	copy(stage1Packet[4:], clientNonce)
	if err := clientSide.WriteMessage(BinaryMessageType, stage1Packet); err != nil {
		t.Fatal(err)
	}

	_, resp, err := clientSide.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 16+256 {
		t.Fatalf("unexpected stage1 response size: %d", len(resp))
	}
	serverNonce := resp[0:16]
	signature := resp[16:272]

	dataToVerify := append(append([]byte{}, clientNonce...), serverNonce...)
	hashed := sha256.Sum256(dataToVerify)
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hashed[:], signature); err != nil {
		t.Fatalf("server signature failed to verify: %v", err)
	}

	curve := ecdh.P256()
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPubBytes := clientPriv.PublicKey().Bytes()

	stage2Packet := make([]byte, 4+len(clientPubBytes))
	binary.LittleEndian.PutUint32(stage2Packet[0:4], 2)
	copy(stage2Packet[4:], clientPubBytes)
	if err := clientSide.WriteMessage(BinaryMessageType, stage2Packet); err != nil {
		t.Fatal(err)
	}

	_, serverPubBytes, err := clientSide.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, err := clientPriv.ECDH(serverPub)
	if err != nil {
		t.Fatal(err)
	}

	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(clientNonce)
	h.Write(serverNonce)
	clientAESKey := h.Sum(nil)

	sess := <-serverSessionCh
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}

	if string(sess.ClientToServerKey) != string(clientAESKey) {
		t.Fatalf("derived AES keys differ:\n server=%x\n client=%x", sess.ClientToServerKey, clientAESKey)
	}

	plaintext := []byte("hello over the secure channel")
	packet, err := EncryptAESGCM(clientAESKey, plaintext, 1)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, seq, err := DecryptAESGCM(sess.ClientToServerKey, packet)
	if err != nil {
		t.Fatalf("server failed to decrypt client message: %v", err)
	}
	if string(decrypted) != string(plaintext) || seq != 1 {
		t.Fatalf("round-trip mismatch: got %q seq=%d", decrypted, seq)
	}
}

// TestHandshakeV1_RejectedByDefault ensures v1 requires an explicit opt-in.
func TestHandshakeV1_RejectedByDefault(t *testing.T) {
	priv := mustGenRSA(t)
	srv := NewServer(priv) // no AllowLegacyV1()

	serverSide, clientSideRaw := newFakeConnPair()
	clientSide := clientConn{clientSideRaw}

	errCh := make(chan error, 1)
	go func() {
		_, err := srv.Perform(context.Background(), serverSide)
		errCh <- err
	}()

	clientNonce := make([]byte, 16)
	if _, err := rand.Read(clientNonce); err != nil {
		t.Fatal(err)
	}
	stage1Packet := make([]byte, 4+16)
	binary.LittleEndian.PutUint32(stage1Packet[0:4], cmdStage1)
	copy(stage1Packet[4:], clientNonce)
	if err := clientSide.WriteMessage(BinaryMessageType, stage1Packet); err != nil {
		t.Fatal(err)
	}

	err := <-errCh
	if err == nil {
		t.Fatal("expected v1 handshake to be rejected by default")
	}
}

// TestHandshakeV2_EndToEnd verifies the v2 transcript signature and key derivation.
func TestHandshakeV2_EndToEnd(t *testing.T) {
	priv := mustGenRSA(t)
	srv := NewServer(priv)

	serverSide, clientSideRaw := newFakeConnPair()
	clientSide := clientConn{clientSideRaw}

	serverSessionCh := make(chan *Session, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		sess, err := srv.Perform(context.Background(), serverSide)
		serverSessionCh <- sess
		serverErrCh <- err
	}()

	clientNonce := make([]byte, 16)
	if _, err := rand.Read(clientNonce); err != nil {
		t.Fatal(err)
	}
	stage1Packet := make([]byte, 4+16)
	binary.LittleEndian.PutUint32(stage1Packet[0:4], cmdStage1V2)
	copy(stage1Packet[4:], clientNonce)
	if err := clientSide.WriteMessage(BinaryMessageType, stage1Packet); err != nil {
		t.Fatal(err)
	}

	_, resp, err := clientSide.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != stage1V2ServerRespSize {
		t.Fatalf("unexpected stage1 v2 response size: %d", len(resp))
	}
	serverNonce := resp

	curve := ecdh.P256()
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPubBytes := clientPriv.PublicKey().Bytes()

	stage2Packet := make([]byte, 4+len(clientPubBytes))
	binary.LittleEndian.PutUint32(stage2Packet[0:4], cmdStage2V2)
	copy(stage2Packet[4:], clientPubBytes)
	if err := clientSide.WriteMessage(BinaryMessageType, stage2Packet); err != nil {
		t.Fatal(err)
	}

	_, stage2Resp, err := clientSide.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if len(stage2Resp) != stage2V2ServerRespSize {
		t.Fatalf("unexpected stage2 v2 response size: %d", len(stage2Resp))
	}
	serverPubBytes := stage2Resp[:65]
	signature := stage2Resp[65:]

	// The signature covers the complete transcript, including both public keys.
	transcript := append(append(append(append([]byte{}, clientNonce...), serverNonce...), clientPubBytes...), serverPubBytes...)
	hashed := sha256.Sum256(transcript)
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hashed[:], signature); err != nil {
		t.Fatalf("transcript signature failed to verify: %v", err)
	}

	serverPub, err := curve.NewPublicKey(serverPubBytes)
	if err != nil {
		t.Fatal(err)
	}
	sharedSecret, err := clientPriv.ECDH(serverPub)
	if err != nil {
		t.Fatal(err)
	}

	clientToServer, serverToClient := deriveV2DirectionalKeys(sharedSecret, clientNonce, serverNonce)

	sess := <-serverSessionCh
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}

	if string(sess.ClientToServerKey) != string(clientToServer) || string(sess.ServerToClientKey) != string(serverToClient) {
		t.Fatalf("derived directional keys differ")
	}
}

// TestHandshakeV2_DetectsSubstitutedServerPubKey rejects a substituted key.
func TestHandshakeV2_DetectsSubstitutedServerPubKey(t *testing.T) {
	priv := mustGenRSA(t)
	srv := NewServer(priv)

	serverSide, clientSideRaw := newFakeConnPair()
	clientSide := clientConn{clientSideRaw}

	go func() { _, _ = srv.Perform(context.Background(), serverSide) }()

	clientNonce := make([]byte, 16)
	if _, err := rand.Read(clientNonce); err != nil {
		t.Fatal(err)
	}
	stage1Packet := make([]byte, 4+16)
	binary.LittleEndian.PutUint32(stage1Packet[0:4], cmdStage1V2)
	copy(stage1Packet[4:], clientNonce)
	if err := clientSide.WriteMessage(BinaryMessageType, stage1Packet); err != nil {
		t.Fatal(err)
	}

	_, serverNonce, err := clientSide.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}

	curve := ecdh.P256()
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPubBytes := clientPriv.PublicKey().Bytes()

	stage2Packet := make([]byte, 4+len(clientPubBytes))
	binary.LittleEndian.PutUint32(stage2Packet[0:4], cmdStage2V2)
	copy(stage2Packet[4:], clientPubBytes)
	if err := clientSide.WriteMessage(BinaryMessageType, stage2Packet); err != nil {
		t.Fatal(err)
	}

	_, stage2Resp, err := clientSide.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	signature := stage2Resp[65:]

	// Simulate an attacker substituting the server's ECDH public key.
	attackerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	substitutedPubBytes := attackerPriv.PublicKey().Bytes()

	transcript := append(append(append(append([]byte{}, clientNonce...), serverNonce...), clientPubBytes...), substitutedPubBytes...)
	hashed := sha256.Sum256(transcript)
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hashed[:], signature); err == nil {
		t.Fatal("expected signature verification to fail against a substituted server public key")
	}
}

func TestLoadPrivateKeyRSA_PKCS1(t *testing.T) {
	priv := mustGenRSA(t)
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	path := t.TempDir() + "/key.pem"
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPrivateKeyRSA(path)
	if err != nil {
		t.Fatalf("LoadPrivateKeyRSA: %v", err)
	}
	if loaded.N.Cmp(priv.N) != 0 {
		t.Fatal("loaded key does not match original")
	}
}

func TestVerifyResumeProof(t *testing.T) {
	masterKey := []byte("test-master-key-32-bytes-long!!")
	sessionSalt := []byte("session-salt")
	authKeyIDBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverNonce := make([]byte, 16)

	ha := hmac.New(sha256.New, masterKey)
	ha.Write(sessionSalt)
	macA := ha.Sum(nil)

	hb := hmac.New(sha256.New, macA)
	hb.Write(authKeyIDBytes)
	hb.Write(serverNonce)
	proofB := hb.Sum(nil)

	if !VerifyResumeProof(masterKey, sessionSalt, authKeyIDBytes, serverNonce, proofB) {
		t.Fatal("expected valid proof to verify")
	}
	if VerifyResumeProof(masterKey, sessionSalt, authKeyIDBytes, serverNonce, []byte("garbage")) {
		t.Fatal("expected tampered proof to fail verification")
	}
}
