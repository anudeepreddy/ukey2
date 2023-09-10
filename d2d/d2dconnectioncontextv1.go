package d2d

import "encoding/binary"

type D2DConnectionContextV1 struct {
	AbstractD2DConnectionContext
	sequenceNumberForEncoding int32
	sequenceNumberForDecoding int32
}

func NewD2DConnectionContextV1(encodeKey []byte, decodeKey []byte, initalEncodeSquenceNumber int32, initalDecodeSquenceNumber int32) D2DConnectionContext {
	d2dConnectionContextV1 := &D2DConnectionContextV1{
		sequenceNumberForEncoding: initalEncodeSquenceNumber,
		sequenceNumberForDecoding: initalDecodeSquenceNumber,
		AbstractD2DConnectionContext: AbstractD2DConnectionContext{
			protocolVersion: 1,
			encodeKey:       encodeKey,
			decodeKey:       decodeKey,
		},
	}
	return d2dConnectionContextV1
}

func (d *D2DConnectionContextV1) incrementSequenceNumberForDecoding() {
	d.sequenceNumberForDecoding += 1
}

func (d *D2DConnectionContextV1) incrementSequenceNumberForEncoding() {
	d.sequenceNumberForEncoding += 1
}

func (d *D2DConnectionContextV1) getSequenceNumberForEncoding() int32 {
	return d.sequenceNumberForEncoding
}

func (d *D2DConnectionContextV1) getSequenceNumberForDecoding() int32 {
	return d.sequenceNumberForDecoding
}

func (d *D2DConnectionContextV1) getDecodeKey() []byte {
	return d.decodeKey
}

func (d *D2DConnectionContextV1) getEncodedKey() []byte {
	return d.encodeKey
}

func (d *D2DConnectionContextV1) SaveSession() []byte {
	session := []byte{1}
	session = binary.BigEndian.AppendUint32(session, uint32(d.sequenceNumberForEncoding))
	session = binary.BigEndian.AppendUint32(session, uint32(d.sequenceNumberForDecoding))
	session = append(session, d.encodeKey...)
	session = append(session, d.decodeKey...)
	return session
}
