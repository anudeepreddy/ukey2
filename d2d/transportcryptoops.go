package d2d

type PayloadType int

const (
	ENROLLMENT PayloadType = iota
	TICKLE
	TX_REQUEST
	TX_REPLY
	TX_SYNC_REQUEST
	TX_SYNC_RESPONSE
	TX_PING
	DEVICE_INFO_UPDATE
	TX_CANCEL_REQUEST
	LOGIN_NOTIFICATION
	PROXIMITYAUTH_PAIRING
	GCMV1_IDENTITY_ASSERTION
	DEVICE_TO_DEVICE_RESPONDER_HELLO_PAYLOAD
	DEVICE_TO_DEVICE_MESSAGE
	DEVICE_PROXIMITY_CALLBACK
	UNLOCK_KEY_SIGNED_CHALLENGE
)

type Payload struct {
	payloadType PayloadType
	message     []byte
}

func NewPayload(payloadType PayloadType, message []byte) *Payload {
	return &Payload{
		payloadType: payloadType,
		message:     message,
	}
}
