package yubikeyring_test

import (
	"github.com/gnzlabs/keyring"
	"github.com/gnzlabs/yubikeyring"
)

type KeyGenTestParams struct {
	Slot          keyring.KeySlot
	Type          keyring.KeyType
	ExpectSuccess bool
}

var keyGenTestParams []*KeyGenTestParams = []*KeyGenTestParams{
	{Slot: keyring.SigningKeySlot, Type: keyring.EC256Key, ExpectSuccess: true},
	{Slot: keyring.SigningKeySlot, Type: keyring.EC384Key, ExpectSuccess: true},
	{Slot: keyring.SigningKeySlot, Type: keyring.ManagementKey, ExpectSuccess: false},
	{Slot: keyring.AuthenticationKeySlot, Type: keyring.EC256Key, ExpectSuccess: true},
	{Slot: keyring.AuthenticationKeySlot, Type: keyring.EC384Key, ExpectSuccess: true},
	{Slot: keyring.AuthenticationKeySlot, Type: keyring.ManagementKey, ExpectSuccess: false},
	{Slot: keyring.EncryptionKeySlot, Type: keyring.EC256Key, ExpectSuccess: true},
	{Slot: keyring.EncryptionKeySlot, Type: keyring.EC384Key, ExpectSuccess: true},
	{Slot: keyring.EncryptionKeySlot, Type: keyring.ManagementKey, ExpectSuccess: false},
	{Slot: keyring.DeviceKeySlot, Type: keyring.EC256Key, ExpectSuccess: true},
	{Slot: keyring.DeviceKeySlot, Type: keyring.EC384Key, ExpectSuccess: true},
	{Slot: keyring.DeviceKeySlot, Type: keyring.ManagementKey, ExpectSuccess: false},
	{Slot: keyring.ManagementKeySlot, Type: keyring.EC256Key, ExpectSuccess: false},
	{Slot: keyring.ManagementKeySlot, Type: keyring.EC384Key, ExpectSuccess: false},
	{Slot: keyring.ManagementKeySlot, Type: keyring.ManagementKey, ExpectSuccess: true},
}

func generatePrivateKeys(yk *yubikeyring.Backend) (err error) {
	if err = yk.Reset(); err == nil {
		if err = yk.CreateKey(keyring.ManagementKeySlot, keyring.ManagementKey); err == nil {
			for i := keyring.SigningKeySlot; i < keyring.ManagementKeySlot; i++ {
				if err = yk.CreateKey(i, keyring.EC384Key); err != nil {
					break
				}
			}
		}
	}
	return
}
