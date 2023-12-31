package yubikeyring

import (
	"strings"
	"sync"

	"github.com/gnzlabs/keyring/errors"
	"github.com/go-piv/piv-go/piv"
)

func getYubikeyName() (name string, err error) {
	if cards, e := piv.Cards(); e != nil {
		err = e
	} else {
		for _, cardName := range cards {
			if strings.Contains(strings.ToLower(cardName), "yubikey") {
				name = cardName
				break
			}
		}
	}
	if name == "" {
		err = errors.ErrKeystoreNotfound
	}
	return
}

func openYubikeyHandle() (handle *piv.YubiKey, err error) {
	if name, e := getYubikeyName(); e != nil {
		err = e
	} else {
		handle, err = piv.Open(name)
	}
	return
}

func New() (backend *Backend, err error) {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if instance == nil {
		if handle, e := openYubikeyHandle(); e != nil {
			err = e
		} else {
			instance = &Backend{
				handle:      handle,
				handleMutex: &sync.Mutex{},
				pinMutex:    &sync.Mutex{},
			}
		}
	}

	backend = instance

	return
}
