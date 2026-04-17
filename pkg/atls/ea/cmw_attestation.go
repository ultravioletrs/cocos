// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ea

const (
	CMWAttestationExtensionType uint16 = 0xFF00
	cmwAttestationLengthBytes          = 2
)

func CMWAttestationOfferExtension() Extension {
	return Extension{Type: CMWAttestationExtensionType, Data: nil}
}

func CMWAttestationDataExtension(cmw []byte) (Extension, error) {
	if len(cmw) == 0 || len(cmw)+cmwAttestationLengthBytes > 0xFFFF {
		return Extension{}, ErrInvalidLength
	}
	data := make([]byte, cmwAttestationLengthBytes+len(cmw))
	putUint16(data[0:2], uint16(len(cmw)))
	copy(data[cmwAttestationLengthBytes:], cmw)
	return Extension{Type: CMWAttestationExtensionType, Data: data}, nil
}

func ExtractCMWAttestationFromExtensions(exts []Extension) ([]byte, bool, error) {
	for _, e := range exts {
		if e.Type != CMWAttestationExtensionType {
			continue
		}
		if len(e.Data) < 2 {
			return nil, true, ErrInvalidLength
		}
		l := int(readUint16(e.Data[0:2]))
		if l <= 0 || l != len(e.Data)-2 {
			return nil, true, ErrInvalidLength
		}
		return append([]byte(nil), e.Data[2:]...), true, nil
	}
	return nil, false, nil
}

func ValidateCMWAttestationPlacement(entries []CertificateEntry) error {
	for i, entry := range entries {
		for _, ext := range entry.Extensions {
			if ext.Type != CMWAttestationExtensionType {
				continue
			}
			if i != 0 {
				return ErrBadRequest
			}
		}
	}
	return nil
}
