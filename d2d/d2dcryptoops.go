package d2d

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strconv"

	"github.com/anudeepreddy/ukey2/pb"
	"github.com/anudeepreddy/ukey2/utils"
	"google.golang.org/protobuf/proto"
)

var (
	D2DSalt            = sha256.Sum256([]byte("D2D"))
	derivationSalt     = sha256.Sum256([]byte("SecureMessage"))
	SECURE_GCM_VERSION = int32(1)
	DIGEST_LENGTH      = 20
)

type SigType struct {
	sigScheme       pb.SigScheme
	jcaName         string
	publicKeyScheme bool
}

func (s *SigType) GetJcaName() string {
	return s.jcaName
}

func (s *SigType) GetSigScheme() pb.SigScheme {
	return s.sigScheme
}

func (s *SigType) IsPublicScheme() bool {
	return s.publicKeyScheme
}

type EncType struct {
	encScheme pb.EncScheme
	jcaName   string
	blockSize int
}

var (
	HMAC_SHA256       = SigType{pb.SigScheme_HMAC_SHA256, "HmacSHA256", false}
	ECDSA_P256_SHA256 = SigType{pb.SigScheme_ECDSA_P256_SHA256, "SHA256withECDSA", true}
	RSA2048_SHA256    = SigType{pb.SigScheme_RSA2048_SHA256, "SHA256withRSA", true}
)

var (
	NONE        = EncType{pb.EncScheme_NONE, "InvalidDoNotUseForJCA", 0}
	AES_256_CBC = EncType{pb.EncScheme_AES_256_CBC, "AES/CBC/PKCS5Padding", 16}
)

func digest(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)
	return digest[:DIGEST_LENGTH]
}

func encrypt(encryptionKey []byte, encType EncType, iv []byte, plainText []byte) ([]byte, error) {
	if encType == NONE {
		return nil, errors.New("cannot use None type here")
	}

	derivedKey := dervieAes256KeyFor(encryptionKey, getPurposeForEncType(encType))

	var ciphertext []byte
	var err error
	switch encType {
	case AES_256_CBC:
		{
			ciphertext, err = utils.Aes256Encrypt(plainText, derivedKey, iv)
		}
	default:
		{
			err = errors.New("failed to encrypt")
		}
	}
	return ciphertext, err
}

func decrypt(decryptionKey []byte, encType EncType, iv []byte, ciphertext []byte) ([]byte, error) {
	if encType == NONE {
		return nil, errors.New("cannot use NONE enctype")
	}

	deriverdKey := dervieAes256KeyFor(decryptionKey, getPurposeForEncType(encType))

	var plaintext []byte
	var err error
	switch encType {
	case AES_256_CBC:
		{
			plaintext, err = utils.Aes256Decrypt(ciphertext, deriverdKey, iv)
		}
	default:
		{
			err = errors.New("failed to decrypt")
		}
	}
	return plaintext, err
}

func signCryptPayload(payload Payload, decryptKey []byte, responderHello []byte) []byte {
	secureMessageBuilder := NewSecureMessageBuilder()
	t := pb.Type(payload.payloadType)
	metaData, _ := proto.Marshal(&pb.GcmMetadata{Type: &t, Version: &SECURE_GCM_VERSION})
	secureMessageBuilder.SetPublicMetaData(metaData)
	if responderHello != nil {
		secureMessageBuilder.SetDecryptionKeyId(responderHello)
	}
	secureMessage, _ := secureMessageBuilder.BuildSignCryptedMessage(decryptKey, HMAC_SHA256, decryptKey, AES_256_CBC, payload.message)
	bSecureMessage, _ := proto.Marshal(secureMessage)
	return bSecureMessage
}

func getPurposeForSigType(sigType SigType) string {
	return "SIG:" + strconv.Itoa(int(sigType.sigScheme))
}

func getPurposeForEncType(encType EncType) string {
	return "ENC:" + strconv.Itoa(int(encType.encScheme))
}

func sign(sigType SigType, signingKey []byte, data []byte) []byte {

	switch sigType {
	case HMAC_SHA256:
		{
			derivedKey := dervieAes256KeyFor(signingKey, getPurposeForSigType(sigType))
			h := hmac.New(sha256.New, derivedKey)
			h.Write(data)
			return h.Sum(nil)
		}

		//   SigType.ECDSA_P256_SHA256 -> TODO()
		//   SigType.RSA2048_SHA256 -> TODO()
	}
	return nil
}

func verify(verificationKey []byte, sigType SigType, signature []byte, data []byte) bool {

	switch sigType {
	case HMAC_SHA256:
		{
			derivedKey := dervieAes256KeyFor(verificationKey, getPurposeForSigType(sigType))
			h := hmac.New(sha256.New, derivedKey)
			h.Write(data)
			return bytes.Equal(h.Sum(nil), signature)
		}

		//   SigType.ECDSA_P256_SHA256 -> TODO()
		//   SigType.RSA2048_SHA256 -> TODO()
	}
	return false
}

func dervieAes256KeyFor(masterKey []byte, purpose string) []byte {
	return utils.Hkdf(sha256.New, masterKey, derivationSalt[:], []byte(purpose), int(32))
}

func verifyDecryptPayload(signCryptedMessage []byte, masterKey []byte) (*Payload, error) {
	secureMessage := &pb.SecureMessage{}
	proto.Unmarshal(signCryptedMessage, secureMessage)
	parsed, err := parseSignCryptedMessage(secureMessage, masterKey, HMAC_SHA256, masterKey, AES_256_CBC)
	if err != nil {
		return nil, err
	}
	if parsed.Header.PublicMetadata == nil {
		return nil, errors.New("missing metadata")
	}

	metadata := &pb.GcmMetadata{}
	proto.Unmarshal(parsed.Header.PublicMetadata, metadata)
	if *metadata.Version != SECURE_GCM_VERSION {
		return nil, errors.New("unsupported protocol version")
	}
	payload := NewPayload(PayloadType(*metadata.Type), parsed.Body)
	return payload, nil
}

func parseSignCryptedMessage(secureMessage *pb.SecureMessage, verificationKey []byte, sigType SigType, decryptionKey []byte, encType EncType) (*pb.HeaderAndBody, error) {
	if encType == NONE {
		return nil, errors.New("not a signcrypted message")
	}
	tagRequired := taggedPlaintextRequired(verificationKey, sigType, decryptionKey)
	headerAndEncryptedBody, err := verifyHeaderAndBody(secureMessage, verificationKey, sigType, encType)
	if err != nil {
		return nil, err
	}

	header := headerAndEncryptedBody.Header

	if header.Iv == nil {
		return nil, errors.New("missing IV")
	}

	rawDecryptedBody, err := decrypt(decryptionKey, encType, header.Iv, headerAndEncryptedBody.Body)

	if err != nil {
		return nil, err
	}

	if !tagRequired {
		return &pb.HeaderAndBody{
				Header: header,
				Body:   rawDecryptedBody,
			},
			nil
	}

	headerAndBodyInternal := &pb.HeaderAndBodyInternal{}
	proto.Unmarshal(secureMessage.HeaderAndBody, headerAndBodyInternal)
	headerBytes := headerAndBodyInternal.Header

	verifiedBinding := false
	expectedTag := digest(headerBytes)
	if len(rawDecryptedBody) >= DIGEST_LENGTH {
		actualTag := rawDecryptedBody[0:DIGEST_LENGTH]
		if bytes.Equal(actualTag, expectedTag) {
			verifiedBinding = true
		}
	}
	if !verifiedBinding {
		return nil, errors.New("tag verification failed")
	}
	headerAndEncryptedBody.Body = rawDecryptedBody[DIGEST_LENGTH:]
	return headerAndEncryptedBody, nil
}

func verifyHeaderAndBody(secureMessage *pb.SecureMessage, verificationKey []byte, sigType SigType, encType EncType) (*pb.HeaderAndBody, error) {
	signature := secureMessage.Signature
	data := secureMessage.HeaderAndBody
	signedData := data

	verified := verify(verificationKey, sigType, signature, signedData)

	result := &pb.HeaderAndBody{}

	_ = proto.Unmarshal(secureMessage.HeaderAndBody, result)

	verified = verified && (*result.Header.SignatureScheme == sigType.sigScheme)
	verified = verified && (*result.Header.EncryptionScheme == encType.encScheme)
	verified = verified && (encType != NONE || result.Header.DecryptionKeyId == nil)
	verified = verified && (encType == NONE || !sigType.publicKeyScheme || result.Header.VerificationKeyId != nil)
	verified = verified && (result.Header.AssociatedDataLength == nil)
	if verified {
		return result, nil
	}

	return nil, errors.New("header verification failed")
}
