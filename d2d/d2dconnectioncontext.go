package d2d

import (
	"encoding/binary"
	"errors"

	"github.com/anudeepreddy/ukey2/pb"
	"google.golang.org/protobuf/proto"
)

type D2DConnectionContext interface {
	incrementSequenceNumberForEncoding() //abstract
	incrementSequenceNumberForDecoding() //abstract
	getSequenceNumberForEncoding() int32
	getSequenceNumberForDecoding() int32
	getEncodedKey() []byte
	getDecodeKey() []byte
	SaveSession() []byte //abstract

}

type AbstractD2DConnectionContext struct {
	protocolVersion int32
	encodeKey       []byte
	decodeKey       []byte
}

func (d2dConnectionContext *AbstractD2DConnectionContext) GetProtocolVersion() int32 {
	return d2dConnectionContext.protocolVersion
}

func (d2dConnectionContext *AbstractD2DConnectionContext) EncodeMessageToPeer(d2dcc D2DConnectionContext, payload []byte) []byte {
	d2dcc.incrementSequenceNumberForEncoding()
	message, _ := proto.Marshal(createDeviceToDeviceMessage(payload, int32(d2dcc.getSequenceNumberForEncoding())))
	return signCryptPayload(*NewPayload(DEVICE_TO_DEVICE_MESSAGE, message), d2dConnectionContext.encodeKey, nil)
}

func (a *AbstractD2DConnectionContext) DecodeMessageFromPeer(d2cc D2DConnectionContext, message []byte) ([]byte, error) {
	payload, err := verifyDecryptPayload(message, a.decodeKey)

	if err != nil {
		return nil, err
	}

	if payload.payloadType != DEVICE_TO_DEVICE_MESSAGE {
		return nil, errors.New("wrong message type in DEVICE_TO_DEVICE_MESSAGE")
	}

	deviceToDeviceMessage := &pb.DeviceToDeviceMessage{}
	proto.Unmarshal(payload.message, deviceToDeviceMessage)
	d2cc.incrementSequenceNumberForDecoding()
	if *deviceToDeviceMessage.SequenceNumber != int32(d2cc.getSequenceNumberForDecoding()) {
		return nil, errors.New("incorrect sequence number")
	}
	return deviceToDeviceMessage.Message, nil
}

func createDeviceToDeviceMessage(message []byte, sequenceNumber int32) *pb.DeviceToDeviceMessage {
	deviceToDeviceMessage := &pb.DeviceToDeviceMessage{
		SequenceNumber: &sequenceNumber,
		Message:        message,
	}
	return deviceToDeviceMessage
}

func FromSavedSession(savedSessionInfo []byte) (D2DConnectionContext, error) {
	if len(savedSessionInfo) == 0 {
		return nil, errors.New("savedSessionInfo null or too short")
	}

	switch protocolVersion := int(savedSessionInfo[0]) & 0xff; protocolVersion {
	// case 0:{
	// 	//not going to implement here, ukey2 uses version 1
	// }
	case 1:
		{
			if len(savedSessionInfo) != 73 {
				return nil, errors.New("incorrect data length for v1 protocol")
			}

			encodeSequenceNumber := int32(binary.BigEndian.Uint32(savedSessionInfo[1:5]))
			decodeSequenceNumber := int32(binary.BigEndian.Uint32(savedSessionInfo[5:9]))
			encodeKey := savedSessionInfo[9:41]
			decodeKey := savedSessionInfo[41:73]
			return NewD2DConnectionContextV1(encodeKey, decodeKey, encodeSequenceNumber, decodeSequenceNumber), nil
		}
	default:
		{
			return nil, errors.New("cannot rebuild context, unknown protocol version")
		}
	}
	// return nil, nil
}
