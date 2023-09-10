package d2d

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/anudeepreddy/ukey2/pb"
	"github.com/anudeepreddy/ukey2/utils"
	"google.golang.org/protobuf/proto"
)

type SecureMessageBuilder struct {
	publicMetadata    []byte
	verificationKeyId []byte
	decryptionKeyId   []byte
	associatedData    []byte
}

func NewSecureMessageBuilder() *SecureMessageBuilder {
	return &SecureMessageBuilder{}
}

func (smb *SecureMessageBuilder) Reset() {
	smb.publicMetadata = nil
	smb.decryptionKeyId = nil
	smb.verificationKeyId = nil
	smb.associatedData = nil
}

func (smb *SecureMessageBuilder) SetPublicMetaData(metadata []byte) {
	smb.publicMetadata = metadata
}

func (smb *SecureMessageBuilder) SetDecryptionKeyId(decryptionKeyId []byte) {
	smb.decryptionKeyId = decryptionKeyId
}

func (smb *SecureMessageBuilder) SetVerificationKeyId(verificationKeyId []byte) {
	smb.verificationKeyId = verificationKeyId
}

func (smb *SecureMessageBuilder) SetAssociatedData(associatedData []byte) {
	smb.associatedData = associatedData
}

func (smb *SecureMessageBuilder) BuildSignedClearTextMessage(signingKey []byte, sigType SigType, body []byte) (*pb.SecureMessage, error) {

	if smb.decryptionKeyId == nil {
		return nil, errors.New("cannot set decryptionId for a cleartext message")
	}
	header, _ := proto.Marshal(smb.buildHeader(sigType, NONE, nil))
	headerAndBody := serializeHeaderAndBody(header, body)
	return createSignedResult(signingKey, sigType, headerAndBody, smb.associatedData), nil
}

func (smb *SecureMessageBuilder) BuildSignCryptedMessage(signingKey []byte, sigType SigType, encryptionKey []byte, encType EncType, body []byte) (*pb.SecureMessage, error) {
	if encType == NONE {
		return nil, errors.New("none not supported for encrypted messages")
	}

	if sigType.publicKeyScheme && smb.verificationKeyId == nil {
		return nil, errors.New("must set a verificationkeyid when using public key signature with encryption")
	}

	iv, _ := utils.SecureRandomBytes(int32(encType.blockSize))

	header, _ := proto.Marshal(smb.buildHeader(sigType, encType, iv))

	var taggedBody []byte
	var associatedDataToBeSigned []byte
	//TODO understand what's happening here
	if taggedPlaintextRequired(signingKey, sigType, encryptionKey) {
		taggedBody = append(digest(append(header, smb.associatedData...)), body...)
		associatedDataToBeSigned = nil
	} else {
		taggedBody = body
		associatedDataToBeSigned = smb.associatedData
	}

	encryptedBody, err := encrypt(encryptionKey, encType, iv, taggedBody)
	if err != nil {
		return nil, err
	}
	headerAndBody := serializeHeaderAndBody(header, encryptedBody)
	return createSignedResult(signingKey, sigType, headerAndBody, associatedDataToBeSigned), nil
}

func (smb *SecureMessageBuilder) buildHeader(sigType SigType, encType EncType, iv []byte) *pb.Header {
	associatedDataLength := uint32(len(smb.associatedData))
	return &pb.Header{
		SignatureScheme:      &sigType.sigScheme,
		EncryptionScheme:     &encType.encScheme,
		VerificationKeyId:    smb.verificationKeyId,
		DecryptionKeyId:      smb.decryptionKeyId,
		PublicMetadata:       smb.publicMetadata,
		AssociatedDataLength: &associatedDataLength,
		Iv:                   iv,
	}
}

func serializeHeaderAndBody(header []byte, body []byte) []byte {
	serializedHeaderAndBody, _ := proto.Marshal(&pb.HeaderAndBodyInternal{
		Header: header,
		Body:   body,
	})
	return serializedHeaderAndBody
}

func createSignedResult(signKey []byte, sigType SigType, headerAndBody []byte, associatedData []byte) *pb.SecureMessage {
	signature := sign(sigType, signKey, append(headerAndBody, associatedData...))
	fmt.Println("signing ket:", signKey)
	fmt.Println("data to be signed:", append(headerAndBody, associatedData...))
	fmt.Println("printign signatire:", signature)
	return &pb.SecureMessage{
		HeaderAndBody: headerAndBody,
		Signature:     signature,
	}
}

func taggedPlaintextRequired(signingKey []byte, sigType SigType, encryptionKey []byte) bool {
	return sigType.publicKeyScheme || !bytes.Equal(signingKey, encryptionKey)
}
