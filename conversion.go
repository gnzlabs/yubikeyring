package yubikeyring

import (
	"github.com/gnzlabs/keyring"
	"github.com/gnzlabs/keyring/errors"
	"github.com/go-piv/piv-go/piv"
)

func convertKeyslotToPivSlot(keyslot keyring.KeySlot) (slot piv.Slot, err error) {
	switch keyslot {
	case keyring.SigningKeySlot:
		slot = piv.SlotSignature
	case keyring.AuthenticationKeySlot:
		slot = piv.SlotAuthentication
	case keyring.EncryptionKeySlot:
		slot = piv.SlotKeyManagement
	case keyring.DeviceKeySlot:
		slot = piv.SlotCardAuthentication
	default:
		err = errors.ErrInvalidKeySlot
	}
	return
}

func convertKeytypeToPivAlg(keytype keyring.KeyType) (alg piv.Algorithm, err error) {
	switch keytype {
	case keyring.EC256Key:
		alg = piv.AlgorithmEC256
	case keyring.EC384Key:
		alg = piv.AlgorithmEC384
	default:
		err = errors.ErrUnsupportedAlgorithm
	}
	return
}
