package syncpair

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"time"
)

const (
	answerVersion         = 1
	maxCheckpointSize     = 8 << 20
	maxAnswerSize         = maxCheckpointSize + (4 << 10)
	answerHPKEDomain      = "PasswordSaver/sync/pair/answer/hpke/v1"
	answerSignatureDomain = "PasswordSaver/sync/pair/answer/sign/v1"
)

type answerHeader struct {
	_              struct{} `cbor:",toarray"`
	Version        uint64
	RequestHash    [32]byte
	MembershipHash [32]byte
}

type signedAnswer struct {
	_          struct{} `cbor:",toarray"`
	Header     answerHeader
	Membership []byte // complete signed membership file as a CBOR byte string
	Enc        [32]byte
	Ciphertext []byte
	Signature  [64]byte
}

// AnswerPayload contains the new epoch key and the opaque initial snapshot.
type AnswerPayload struct {
	_          struct{} `cbor:",toarray"`
	EpochKey   [32]byte
	Checkpoint []byte
}

// IssuedAnswerMatchesRequest checks the binding in an answer from authenticated local storage.
func IssuedAnswerMatchesRequest(wire []byte, digest [32]byte) bool {
	var answer signedAnswer
	return len(wire) <= maxAnswerSize && decodeCanonicalPairing(wire, &answer) == nil && answer.Header.RequestHash == digest
}

// IssueAnswer adds the requester to the initial membership and encrypts the payload.
// confirmedRequest must be the fingerprint independently confirmed by the owner.
func (keys *SpaceKeys) IssueAnswer(initial, requestWire []byte, confirmedRequest [32]byte, payload AnswerPayload, now time.Time) ([]byte, error) {
	if len(payload.Checkpoint) > maxCheckpointSize {
		return nil, errors.New("pairing checkpoint exceeds size limit")
	}
	request, digest, err := ParseRequest(requestWire, now)
	if err != nil {
		return nil, err
	}
	if digest != confirmedRequest {
		return nil, errors.New("pairing request fingerprint mismatch")
	}
	h := request.Header
	member := Member{DeviceID: h.DeviceID, SigningPub: h.SigningPub, ExchangePub: h.ExchangePub}
	membership, err := keys.AddMember(initial, h.ControllerFingerprint, member)
	if err != nil {
		return nil, err
	}
	answer := signedAnswer{Header: answerHeader{Version: answerVersion, RequestHash: digest, MembershipHash: sha256.Sum256(membership)},
		Membership: membership}
	aad, err := encMode.Marshal(answer.Header)
	if err != nil {
		return nil, err
	}
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(h.ExchangePub[:])
	if err != nil {
		return nil, err
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(answerHPKEDomain))
	if err != nil {
		return nil, err
	}
	answer.Enc = [32]byte(enc)
	if payload.Checkpoint == nil {
		payload.Checkpoint = []byte{}
	}
	plaintext, err := encMode.Marshal(payload)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	answer.Ciphertext, err = sender.Seal(aad, plaintext)
	if err != nil {
		return nil, err
	}
	message, err := answer.signatureInput()
	if err != nil {
		return nil, err
	}
	answer.Signature = [64]byte(ed25519.Sign(keys.controller, message))
	return encMode.Marshal(answer)
}

// OpenAnswer checks the signed membership against the confirmed controller and
// verifies the answer against the original request before opening the payload.
func (keys *DeviceKeys) OpenAnswer(wire, requestWire []byte, confirmedController [32]byte, now time.Time) (Membership, AnswerPayload, error) {
	if len(wire) > maxAnswerSize {
		return Membership{}, AnswerPayload{}, errors.New("pairing answer exceeds size limit")
	}
	var answer signedAnswer
	if err := decodeCanonicalPairing(wire, &answer); err != nil {
		return Membership{}, AnswerPayload{}, err
	}
	request, digest, err := ParseRequest(requestWire, now)
	if err != nil {
		return Membership{}, AnswerPayload{}, err
	}
	if answer.Header.Version != answerVersion || answer.Header.RequestHash != digest ||
		answer.Header.MembershipHash != sha256.Sum256(answer.Membership) || request.Header.ControllerFingerprint != confirmedController {
		return Membership{}, AnswerPayload{}, errors.New("pairing answer does not match the request or membership")
	}
	membership, err := verifySignedMembership(answer.Membership, confirmedController)
	if err != nil {
		return Membership{}, AnswerPayload{}, err
	}
	h, requested := membership.Header, request.Header
	member := Member{DeviceID: requested.DeviceID, SigningPub: requested.SigningPub, ExchangePub: requested.ExchangePub}
	if h.Revision != 2 || h.Epoch != 2 || h.PrevHash == [32]byte{} || len(h.Members) != 2 || h.Members[1] != member {
		return Membership{}, AnswerPayload{}, errors.New("pairing membership does not include the requested device")
	}
	message, err := answer.signatureInput()
	if err != nil {
		return Membership{}, AnswerPayload{}, err
	}
	if !ed25519.Verify(h.ControllerPub[:], message, answer.Signature[:]) {
		return Membership{}, AnswerPayload{}, errors.New("invalid pairing answer signature")
	}
	if keys == nil || keys.exchange == nil || len(keys.signing) != ed25519.PrivateKeySize ||
		!bytes.Equal(keys.signing[ed25519.SeedSize:], member.SigningPub[:]) || !bytes.Equal(keys.exchange.PublicKey().Bytes(), member.ExchangePub[:]) {
		return Membership{}, AnswerPayload{}, errors.New("pairing answer does not match the recipient keys")
	}
	payload, err := answer.openPayload(keys.exchange)
	if err != nil {
		return Membership{}, AnswerPayload{}, err
	}
	return membership, payload, nil
}

func (a signedAnswer) openPayload(exchange *ecdh.PrivateKey) (AnswerPayload, error) {
	aad, err := encMode.Marshal(a.Header)
	if err != nil {
		return AnswerPayload{}, err
	}
	key, err := hpke.NewDHKEMPrivateKey(exchange)
	if err != nil {
		return AnswerPayload{}, err
	}
	recipient, err := hpke.NewRecipient(a.Enc[:], key, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(answerHPKEDomain))
	if err != nil {
		return AnswerPayload{}, err
	}
	plaintext, err := recipient.Open(aad, a.Ciphertext)
	if err != nil {
		return AnswerPayload{}, err
	}
	defer clear(plaintext)
	var payload AnswerPayload
	if err := decodeCanonicalPairing(plaintext, &payload); err != nil {
		return AnswerPayload{}, err
	}
	if payload.Checkpoint == nil || len(payload.Checkpoint) > maxCheckpointSize {
		return AnswerPayload{}, errors.New("invalid pairing checkpoint")
	}
	return payload, nil
}

func (a signedAnswer) signatureInput() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(answerSignatureDomain)
	err := encMode.NewEncoder(&buffer).Encode([]any{a.Header, a.Membership, a.Enc, a.Ciphertext})
	return buffer.Bytes(), err
}

func decodeCanonicalPairing(wire []byte, value any) error {
	if err := decMode.Unmarshal(wire, value); err != nil {
		return err
	}
	canonical, err := encMode.Marshal(value)
	defer clear(canonical)
	if err != nil || !bytes.Equal(wire, canonical) {
		return errors.New("non-canonical pairing CBOR")
	}
	return nil
}
