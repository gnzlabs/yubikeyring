package yubikeyring_test

import (
	"testing"

	"github.com/gnzlabs/yubikeyring"
)

func openYubikey(t *testing.T) (yk *yubikeyring.Backend, err error) {
	if yk, err = yubikeyring.New(); err != nil {
		t.Errorf("failed to get new yubikey: %s", err)
	}
	return
}

func newOpenAndUnlockedYubikey(pin []byte, t *testing.T) (yk *yubikeyring.Backend, err error) {
	if yk, err = openYubikey(t); err == nil {
		err = yk.Unlock(pin)
	}
	return
}
