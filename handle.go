package yubikeyring

import (
	"github.com/gnzlabs/keyring/errors"
	"github.com/go-piv/piv-go/piv"
)

func (y *Backend) getYubikeyHandle() (handle *piv.YubiKey, err error) {
	if y.handle == nil {
		err = errors.ErrKeystoreHandleClosed
	} else {
		y.handleMutex.Lock()
		handle = y.handle
	}
	return
}

func (y *Backend) releaseYubikeyHandle() {
	y.handleMutex.Unlock()
}
