package yubikeyring

import (
	"crypto/rand"

	"github.com/gnzlabs/keyring"
	"github.com/gnzlabs/keyring/errors"
	"github.com/go-piv/piv-go/piv"
)

func (y *Backend) createPivKey(slot piv.Slot, alg piv.Algorithm) (err error) {
	if key, e := y.getPrivateKey(slot); key != nil {
		err = errors.ErrKeyAlreadyExists
	} else if e != nil && e != errors.ErrKeyNotFound {
		err = e
	} else if mk, e := y.GetPrivateKey(keyring.ManagementKeySlot); e != nil {
		err = e
	} else if managementKey, ok := mk.(*[24]byte); !ok {
		err = errors.ErrInvalidManagementKey
	} else if handle, e := y.getYubikeyHandle(); e != nil {
		err = e
	} else {
		defer y.releaseYubikeyHandle()
		_, err = handle.GenerateKey(*managementKey, slot, piv.Key{
			PINPolicy:   piv.PINPolicyAlways,
			TouchPolicy: piv.TouchPolicyAlways,
			Algorithm:   alg,
		})
	}
	return
}

func (y *Backend) createManagementKey() (err error) {
	var newKey [ManagementKeySize]byte
	if bytesRead, e := rand.Read(newKey[:]); e != nil {
		err = e
	} else if bytesRead != int(ManagementKeySize) {
		err = errors.ErrKeyGenFailed
	} else if managmentKey, e := y.GetPrivateKey(keyring.ManagementKeySlot); e != nil {
		err = e
	} else if managmentKey, ok := managmentKey.(*[24]byte); !ok {
		err = errors.ErrInvalidManagementKey
	} else if handle, e := y.getYubikeyHandle(); e != nil {
		err = e
	} else {
		defer y.releaseYubikeyHandle()
		if err = handle.SetManagementKey(*managmentKey, newKey); err == nil {
			err = handle.SetMetadata(newKey, &piv.Metadata{ManagementKey: &newKey})
		}
	}
	return
}
