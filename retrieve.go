package yubikeyring

import (
	"crypto"

	"github.com/awnumar/memguard"
	"github.com/gnzlabs/keyring/errors"
	"github.com/go-piv/piv-go/piv"
)

func (y *Backend) getPin() (pin *memguard.LockedBuffer, err error) {
	y.pinMutex.Lock()
	defer y.pinMutex.Unlock()
	if y.pin == nil {
		err = errors.ErrKeystoreLocked
	} else {
		pin, err = y.pin.Open()
	}
	return
}

func (y *Backend) getManagementKey() (managementKey *[24]byte, err error) {
	if pin, e := y.getPin(); e != nil {
		err = e
	} else if handle, e := y.getYubikeyHandle(); e != nil {
		err = e
	} else {
		defer y.releaseYubikeyHandle()
		if metadata, e := handle.Metadata(pin.String()); e != nil {
			err = e
		} else if metadata == nil {
			err = errors.ErrKeyNotFound
		} else if metadata.ManagementKey == nil {
			managementKey = &piv.DefaultManagementKey
		} else {
			managementKey = metadata.ManagementKey
		}
	}
	return
}

func (y *Backend) getPublicKey(slot piv.Slot) (key crypto.PublicKey, err error) {
	if handle, e := y.getYubikeyHandle(); e != nil {
		err = e
	} else {
		defer y.releaseYubikeyHandle()
		if cert, e := handle.Attest(slot); e != nil {
			if e == piv.ErrNotFound {
				err = errors.ErrKeyNotFound
			} else {
				err = e
			}
		} else if cert == nil {
			err = errors.ErrKeyNotFound
		} else {
			key = cert.PublicKey
		}
	}
	return
}

func (y *Backend) getPrivateKey(slot piv.Slot) (key crypto.PrivateKey, err error) {
	if pubkey, e := y.getPublicKey(slot); e != nil {
		err = e
	} else if handle, e := y.getYubikeyHandle(); e != nil {
		err = e
	} else {
		defer y.releaseYubikeyHandle()
		if pin, e := y.getPin(); e != nil {
			err = e
		} else {
			key, err = handle.PrivateKey(slot, pubkey, piv.KeyAuth{PIN: pin.String()})
		}
	}
	return
}
