// Copyright 2018 Thales UK Limited
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package p11

import (
	"testing"

	"encoding/binary"

	"fmt"

	"time"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
)

func TestBoolToStr(t *testing.T) {
	attribute := pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true)
	assert.Equal(t, "true", boolToStr(attribute.Value))

	attribute = pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false)
	assert.Equal(t, "false", boolToStr(attribute.Value))
}

func TestULongToStr(t *testing.T) {
	attribute := pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32)
	assert.Equal(t, "32", ulongToStr(attribute.Value))
}

func TestBytesToStr(t *testing.T) {
	assert.Equal(t, "010203040a (hex)", bytesToStr([]byte{1, 2, 3, 4, 0xa}))
}

func TestStrToStr(t *testing.T) {
	const str = "foo"
	attribute := pkcs11.NewAttribute(pkcs11.CKA_LABEL, str)
	assert.Equal(t, str, stringToStr(attribute.Value))
}

func TestIdToStr(t *testing.T) {
	const printableId = "foobar"
	attribute := pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(printableId))
	assert.Equal(t, printableId, idToStr(attribute.Value))

	unprintableId := []byte{0, 1, 2, 3}
	assert.Equal(t, bytesToStr(unprintableId), idToStr(unprintableId))
}

func TestUnknown(t *testing.T) {
	unknownType := []byte{0x42, 0x43, 0x44, 0x4A}
	assert.Equal(t, "Unknown: 0x4243444A", unknownToStr(unknownType))
}

func TestMechToStr(t *testing.T) {
	attribute := pkcs11.NewAttribute(pkcs11.CKA_MECHANISM_TYPE, pkcs11.CKM_AES_CBC)
	assert.Equal(t, "CKM_AES_CBC", mechToStr(attribute.Value))

	notARealMech := []byte{0xA1, 0xA2, 0xA3, 0xA4}
	assert.Equal(t, unknownToStr(notARealMech), mechToStr(notARealMech))
}

func TestMechArrayToStr(t *testing.T) {
	// No support for mechanism arrays in `pkcs11.NewAttribute`
	mechArray := make([]byte, 8)
	binary.LittleEndian.PutUint32(mechArray, uint32(pkcs11.CKM_AES_CBC))
	binary.LittleEndian.PutUint32(mechArray[4:], uint32(pkcs11.CKM_AES_CMAC))

	assert.Equal(t, "[CKM_AES_CBC CKM_AES_CMAC]", mechArrayToStr(mechArray))

	mechArray[4] = 0xFF
	assert.Equal(t, fmt.Sprintf("[CKM_AES_CBC %s]", unknownToStr(mechArray[4:])), mechArrayToStr(mechArray))
}

func TestClassToStr(t *testing.T) {
	attribute := pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY)
	assert.Equal(t, "CKO_SECRET_KEY", classToStr(attribute.Value))

	badClass := attribute.Value
	badClass[0] = 0xFF
	assert.Equal(t, unknownToStr(badClass), classToStr(badClass))
}

func TestKeyTypeToStr(t *testing.T) {
	attribute := pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA)
	assert.Equal(t, "CKK_RSA", keyTypeToStr(attribute.Value))

	badType := attribute.Value
	badType[0] = 0xFF
	assert.Equal(t, unknownToStr(badType), keyTypeToStr(badType))
}

func TestDateToStr(t *testing.T) {
	testDate := time.Date(1999, 12, 31, 0, 0, 0, 0, time.UTC)
	attribute := pkcs11.NewAttribute(pkcs11.CKA_START_DATE, testDate)
	assert.Equal(t, "1999-12-31", dateToStr(attribute.Value))
}
