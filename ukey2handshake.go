package ukey2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/anudeepreddy/ukey2/d2d"
	"github.com/anudeepreddy/ukey2/pb"
	"github.com/anudeepreddy/ukey2/utils"
	"google.golang.org/protobuf/proto"
)

var (
	kNonceLengthInBytes int32  = 32
	kNextProtocol       string = "AES_256_CBC-HMAC_SHA256"
	kVersion            int32  = 1
)

type handshakeState int

const (
	CLIENT_START handshakeState = iota
	CLIENT_WAITING_FOR_SERVER_INIT
	CLIENT_AFTER_SERVER_INIT

	// Responder/server state
	SERVER_START
	SERVER_AFTER_CLIENT_INIT
	SERVER_WAITING_FOR_CLIENT_FINISHED

	// Common completion state
	HANDSHAKE_VERIFICATION_NEEDED
	HANDSHAKE_VERIFICATION_IN_PROGRESS
	HANDSHAKE_FINISHED
	HANDSHAKE_ALREADY_USED
	HANDSHAKE_ERROR
)

type handshakeRole int

const (
	CLIENT handshakeRole = iota
	SERVER
)

type HandShakeCipher int32

type UKey2Handshake struct {
	internalState    handshakeState
	role             handshakeRole
	cipher           HandShakeCipher
	ourkeypair       *ecdsa.PrivateKey
	theirPublicKey   *ecdsa.PublicKey
	rawClientInit    []byte
	rawServerInit    []byte
	rawMessage3Map   map[HandShakeCipher][]byte
	peerCommitment   []byte
	derivedSecretKey []byte
}

const (
	P256_SHA512 HandShakeCipher = 100
)

func ForInitiator(cipher HandShakeCipher) *UKey2Handshake {
	return newUKey2Handshake(CLIENT_START, cipher)
}

func ForResponder(cipher HandShakeCipher) *UKey2Handshake {
	return newUKey2Handshake(SERVER_START, cipher)
}

func newUKey2Handshake(state handshakeState, cipher HandShakeCipher) *UKey2Handshake {
	role := CLIENT
	if state != CLIENT_START {
		role = SERVER
	}

	//generate ecdsa keypair
	privateKey := generateKeyPair(cipher)

	return &UKey2Handshake{
		internalState:  state,
		role:           role,
		cipher:         cipher,
		ourkeypair:     privateKey,
		rawMessage3Map: make(map[HandShakeCipher][]byte),
	}
}

func makeUkey2Message(messageType pb.Ukey2Message_Type, data []byte) []byte {
	ukey2Message, _ := proto.Marshal(&pb.Ukey2Message{
		MessageType: &messageType,
		MessageData: data,
	})
	return ukey2Message
}

func (u *UKey2Handshake) makeClientInitUkey2Message() ([]byte, error) {
	nonce, err := utils.SecureRandomBytes(kNonceLengthInBytes)
	if err != nil {
		return nil, errors.New("failed to generate nonce")
	}

	handshakeCipherCommitment := u.generateP256SHA512Commitment()

	clientInit, _ := proto.Marshal(&pb.Ukey2ClientInit{
		Version:           &kVersion,
		Random:            nonce,
		NextProtocol:      &kNextProtocol,
		CipherCommitments: []*pb.Ukey2ClientInit_CipherCommitment{handshakeCipherCommitment},
	})

	return makeUkey2Message(pb.Ukey2Message_CLIENT_INIT, clientInit), nil
}

func (u *UKey2Handshake) makeServerInitUkey2Message() ([]byte, error) {
	nonce, err := utils.SecureRandomBytes(kNonceLengthInBytes)
	if err != nil {
		return nil, errors.New("failed to generate nonce")
	}

	genericPublicKey := encodeEcdsaPublicKey(&u.ourkeypair.PublicKey)

	serverInit, _ := proto.Marshal(&pb.Ukey2ServerInit{
		Version:         &kVersion,
		Random:          nonce,
		HandshakeCipher: pb.Ukey2HandshakeCipher_P256_SHA512.Enum(),
		PublicKey:       genericPublicKey,
	})
	return makeUkey2Message(pb.Ukey2Message_SERVER_INIT, serverInit), nil
}

func (u *UKey2Handshake) generateP256SHA512Commitment() *pb.Ukey2ClientInit_CipherCommitment {

	if _, ok := u.rawMessage3Map[P256_SHA512]; !ok {
		u.generateP256SHA512ClientFinished(u.ourkeypair)
	}

	commitment := sha512.Sum512(u.rawMessage3Map[P256_SHA512])

	cipherCommitment := &pb.Ukey2ClientInit_CipherCommitment{
		HandshakeCipher: pb.Ukey2HandshakeCipher_P256_SHA512.Enum(),
		Commitment:      commitment[:],
	}
	return cipherCommitment
}

func encodeEcdsaPublicKey(publicKey *ecdsa.PublicKey) []byte {
	genericPublicKey, _ := proto.Marshal(&pb.GenericPublicKey{
		Type: pb.PublicKeyType_EC_P256.Enum(),
		EcP256PublicKey: &pb.EcP256PublicKey{
			X: publicKey.X.FillBytes(make([]byte, 33)),
			Y: publicKey.Y.FillBytes(make([]byte, 33)),
		},
	})
	return genericPublicKey
}

func (u *UKey2Handshake) generateP256SHA512ClientFinished(keypair *ecdsa.PrivateKey) {
	encodedKey := encodeEcdsaPublicKey(&keypair.PublicKey)
	clientFinished, _ := proto.Marshal(&pb.Ukey2ClientFinished{
		PublicKey: encodedKey,
	})

	u.rawMessage3Map[P256_SHA512] = makeUkey2Message(pb.Ukey2Message_CLIENT_FINISH, clientFinished)
}

func generateKeyPair(cipher HandShakeCipher) *ecdsa.PrivateKey {
	switch cipher {
	case P256_SHA512:
		{
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				// TODO: log error and abort
			}
			return privateKey
		}
	default:
		return nil
	}
}

func (u *UKey2Handshake) GetNextHandshakeMessage() ([]byte, error) {
	switch u.internalState {
	case CLIENT_START:
		{
			clientInitMessage, err := u.makeClientInitUkey2Message()

			if err != nil {
				return nil, err
			}

			u.rawClientInit = clientInitMessage
			u.internalState = CLIENT_WAITING_FOR_SERVER_INIT

			return clientInitMessage, nil
		}
	case SERVER_AFTER_CLIENT_INIT:
		{
			serverInitMessage, err := u.makeServerInitUkey2Message()

			if err != nil {
				return nil, err
			}
			u.rawServerInit = serverInitMessage
			u.internalState = SERVER_WAITING_FOR_CLIENT_FINISHED
			return serverInitMessage, nil
		}
	case CLIENT_AFTER_SERVER_INIT:
		{
			clientFinished, ok := u.rawMessage3Map[u.cipher]

			if !ok {
				return nil, errors.New("client finished message has not been generated")
			}

			u.internalState = HANDSHAKE_VERIFICATION_NEEDED
			return clientFinished, nil
		}
	default:
		{
			return nil, errors.New("Cannot get next message")
		}
	}
}

func (u *UKey2Handshake) ParseHandshakeMessage(message []byte) (bool, []byte, error) {
	switch u.internalState {
	case SERVER_START:
		{
			v1, v2 := u.parseClientInitUkey2Message(message)
			u.internalState = SERVER_AFTER_CLIENT_INIT
			return v1, v2, nil
		}
	case CLIENT_WAITING_FOR_SERVER_INIT:
		{
			v1, v2 := u.parseServerInitUkey2Message(message)
			u.internalState = CLIENT_AFTER_SERVER_INIT
			return v1, v2, nil
		}
	case SERVER_WAITING_FOR_CLIENT_FINISHED:
		{
			err := u.parseClientFinishUkey2Message(message)
			if err != nil {
				return false, nil, err
			}
			u.internalState = HANDSHAKE_VERIFICATION_NEEDED
			return true, nil, nil
		}
	default:
		{
			return false, nil, errors.New("Cannot parse message in this state")
		}
	}

}

func (u *UKey2Handshake) parseClientInitUkey2Message(rawMessage []byte) (bool, []byte) {
	message := &pb.Ukey2Message{}
	err := proto.Unmarshal(rawMessage, message)

	if err != nil {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_MESSAGE, "can't parse client init message")
	}

	if message.MessageType == nil || *message.MessageType != pb.Ukey2Message_CLIENT_INIT {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_MESSAGE_TYPE, "expected, but did not find ClientInit message type")
	}

	if message.MessageData == nil {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_MESSAGE_DATA, "expected message data, but did not find it")
	}

	clientInit := &pb.Ukey2ClientInit{}
	err = proto.Unmarshal(message.MessageData, clientInit)
	if err != nil {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_MESSAGE_DATA, "cannot parse message data into ClientInit")
	}

	if *clientInit.Version != 1 {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_VERSION, "Ukey2 version mismatch")
	}

	if len(clientInit.Random) != int(kNonceLengthInBytes) {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_RANDOM, "ClientInit has bad nonce length. Expected 32 bytes")
	}

	if len(clientInit.CipherCommitments) == 0 {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_HANDSHAKE_CIPHER, "ClientInit is missing cipher commitments")
	}

	for _, cipherCommitment := range clientInit.CipherCommitments {
		if int32(*cipherCommitment.HandshakeCipher) == int32(P256_SHA512) {
			u.peerCommitment = cipherCommitment.Commitment
		}
	}

	if *clientInit.NextProtocol != kNextProtocol {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_NEXT_PROTOCOL, "unsupported next protocol, only supports "+kNextProtocol)
	}
	u.rawClientInit = rawMessage
	return true, nil
}

func (u *UKey2Handshake) parseServerInitUkey2Message(rawMessage []byte) (bool, []byte) {
	message := &pb.Ukey2Message{}
	err := proto.Unmarshal(rawMessage, message)
	if err != nil {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_MESSAGE, "Cannot parse ServerInit message")
	}

	if *message.MessageType != pb.Ukey2Message_SERVER_INIT {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_MESSAGE_TYPE, "Expected, but did not find SERVER_INIT message type")
	}

	serverInit := &pb.Ukey2ServerInit{}
	err = proto.Unmarshal(message.MessageData, serverInit)

	if err != nil {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_MESSAGE_DATA, "Cannot parse message data into ServerInit")
	}

	if *serverInit.Version != kVersion {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_VERSION, "Ukey2 version mismatch")
	}

	if len(serverInit.Random) != int(kNonceLengthInBytes) {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_RANDOM, "ServerInit has bad nonce length. Expected 32 bytes")
	}

	genericPublicKey := &pb.GenericPublicKey{}

	err = proto.Unmarshal(serverInit.PublicKey, genericPublicKey)

	if err != nil {
		return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_PUBLIC_KEY, "cannot parse GenericPublic Key")
	}

	switch *serverInit.HandshakeCipher {
	case pb.Ukey2HandshakeCipher_P256_SHA512:
		{
			u.theirPublicKey, err = parseEcdsaPublicKey(*genericPublicKey)
			if err != nil {
				return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_PUBLIC_KEY, err.Error())
			}
		}
	default:
		{
			return false, createAlertUkey2Message(pb.Ukey2Alert_BAD_HANDSHAKE_CIPHER, "No acceptable handshake cipher found")
		}
	}
	u.rawServerInit = rawMessage
	return true, nil
}

func (u *UKey2Handshake) parseClientFinishUkey2Message(rawMessage []byte) error {
	message := &pb.Ukey2Message{}
	err := proto.Unmarshal(rawMessage, message)

	if err != nil {
		return errors.New("Cannot parse ClientFinished message")
	}

	if *message.MessageType != pb.Ukey2Message_CLIENT_FINISH {
		return errors.New("Expected, but did not find CLIENT_FINISH message type")
	}

	if !u.verifyCommitment(rawMessage) {
		return errors.New("failed to verify commitment")
	}

	clientFinished := &pb.Ukey2ClientFinished{}

	err = proto.Unmarshal(message.MessageData, clientFinished)
	if err != nil {
		return errors.New("failed to parse messageData into ClientFinished")
	}

	genericPublicKey := &pb.GenericPublicKey{}

	err = proto.Unmarshal(clientFinished.PublicKey, genericPublicKey)

	if err != nil {
		return errors.New("cannot parse GenericPublic Key")
	}

	u.theirPublicKey, err = parseEcdsaPublicKey(*genericPublicKey)

	if err != nil {
		return err
	}
	return nil
}

func (u *UKey2Handshake) verifyCommitment(handshakeMessage []byte) bool {
	actualClientFinishHash := sha512.Sum512(handshakeMessage)

	return bytes.Equal(actualClientFinishHash[:], u.peerCommitment)
}

func parseEcdsaPublicKey(pubKey pb.GenericPublicKey) (*ecdsa.PublicKey, error) {

	x, y := new(big.Int), new(big.Int)

	if pubKey.EcP256PublicKey == nil || pubKey.EcP256PublicKey.X == nil || pubKey.EcP256PublicKey.Y == nil {
		return nil, errors.New("Error parsing EcP256 Publickey")
	}

	x.SetBytes(pubKey.EcP256PublicKey.X)
	y.SetBytes(pubKey.EcP256PublicKey.Y)

	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return &publicKey, nil
}

func createAlertUkey2Message(alertType pb.Ukey2Alert_AlertType, errorMessage string) []byte {
	ukey2Alert, _ := proto.Marshal(&pb.Ukey2Alert{
		Type:         &alertType,
		ErrorMessage: &errorMessage,
	})

	ukey2Message, _ := proto.Marshal(&pb.Ukey2Message{
		MessageType: pb.Ukey2Message_ALERT.Enum(),
		MessageData: ukey2Alert,
	})

	return ukey2Message
}

func (u *UKey2Handshake) GetVerificationString(byteLength int) ([]byte, error) {

	if byteLength < 1 || byteLength > 32 {
		return nil, errors.New("Minimum length is 1 byte, max is 32 bytes")
	}

	if u.internalState != HANDSHAKE_VERIFICATION_NEEDED {
		return nil, errors.New("Unexpected state")
	}

	//TODO: move this to cryptoops
	r, _ := u.theirPublicKey.Curve.ScalarMult(u.theirPublicKey.X, u.theirPublicKey.Y, u.ourkeypair.D.Bytes())
	sharedKeyDhs := sha256.Sum256(r.Bytes())
	authString := utils.Hkdf(sha256.New, sharedKeyDhs[:], []byte("UKEY2 v1 auth"), append(u.rawClientInit, u.rawServerInit...), byteLength)

	u.derivedSecretKey = sharedKeyDhs[:]
	u.internalState = HANDSHAKE_VERIFICATION_IN_PROGRESS

	return authString, nil
}

func (u *UKey2Handshake) ToConnectionContext() (d2d.D2DConnectionContext, error) {
	fmt.Println("current state:", u.internalState)
	if u.internalState != HANDSHAKE_FINISHED {
		return nil, errors.New("unexpected state")
	}
	//TODO: return error if derived key is nil

	if u.derivedSecretKey == nil {
		return nil, errors.New("derived secret not found")
	}

	info := append(u.rawClientInit, u.rawServerInit...)
	saltNext := []byte("UKEY2 v1 next")

	nextProtocolKey := utils.Hkdf(sha256.New, u.derivedSecretKey, saltNext, info, 32)

	fmt.Println("next protocol key:", nextProtocolKey)
	clientKey := utils.Hkdf(sha256.New, nextProtocolKey, d2d.D2DSalt[:], []byte("client"), 32)
	fmt.Println("client key:", clientKey)
	serverKey := utils.Hkdf(sha256.New, nextProtocolKey, d2d.D2DSalt[:], []byte("server"), 32)
	fmt.Println("server key:", serverKey)
	u.internalState = HANDSHAKE_ALREADY_USED

	if u.role == CLIENT {
		return d2d.NewD2DConnectionContextV1(clientKey, serverKey, 0, 0), nil
	}
	return d2d.NewD2DConnectionContextV1(serverKey, clientKey, 0, 0), nil
}

func (u *UKey2Handshake) VerifyHandshake() error {
	if u.internalState != HANDSHAKE_VERIFICATION_IN_PROGRESS {
		return errors.New("unexpected state: $handshakeState")
	}
	u.internalState = HANDSHAKE_FINISHED
	return nil
}
