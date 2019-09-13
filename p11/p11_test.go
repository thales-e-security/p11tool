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

	"bytes"

	"github.com/golang/mock/gomock"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"github.com/thales-e-security/p11tool/p11/mocks"
)

const tokenLabel = "someToken"
const tokenPIN = "1234"
const slotNumber uint = 42

// prepMockForLogin creates a mock object that expects the usual method calls up to and including the
// log in to the token. Callers to this method should immediately defer a call to controller.Finish().
func prepMockForLogin(t *testing.T) (*gomock.Controller, *mocks.MockTokenCtx, pkcs11.SessionHandle) {
	mockCtrl := gomock.NewController(t)
	mockTokenCtx := mocks.NewMockTokenCtx(mockCtrl)

	slotList := []uint{slotNumber}
	session := pkcs11.SessionHandle(64)

	// Setup
	mockTokenCtx.EXPECT().Initialize()
	mockTokenCtx.EXPECT().GetSlotList(true).Return(slotList, nil)
	mockTokenCtx.EXPECT().GetTokenInfo(slotList[0]).Return(pkcs11.TokenInfo{Label: tokenLabel}, nil)
	mockTokenCtx.EXPECT().OpenSession(slotList[0], gomock.Any()).Return(session, nil)
	mockTokenCtx.EXPECT().Login(session, pkcs11.CKU_USER, tokenPIN).Return(nil)

	return mockCtrl, mockTokenCtx, session
}

func TestP11Token_DeleteAllExcept(t *testing.T) {
	mockCtrl, mockTokenCtx, session := prepMockForLogin(t)
	defer mockCtrl.Finish()

	keyLabels := []string{"keep1", "keep2", "delete1", "delete2"}

	///////////////// MOCK EXPECTATIONS /////////////////

	mockTokenCtx.EXPECT().FindObjectsInit(session, nil).Return(nil)

	// We pass back an extra object handle (4) which will have no label
	firstCall := mockTokenCtx.EXPECT().FindObjects(session, gomock.Any()).Return([]pkcs11.ObjectHandle{0, 1, 2, 3, 4}, false, nil)

	mockTokenCtx.EXPECT().FindObjects(session, gomock.Any()).Return(nil, false, nil).After(firstCall)
	mockTokenCtx.EXPECT().FindObjectsFinal(session).Return(nil)

	for i, label := range keyLabels {
		mockTokenCtx.EXPECT().GetAttributeValue(session, pkcs11.ObjectHandle(i),
			gomock.Any()).Return([]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}, nil)
	}

	mockTokenCtx.EXPECT().GetAttributeValue(session, pkcs11.ObjectHandle(4),
		gomock.Any()).Return(nil, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID))

	mockTokenCtx.EXPECT().DestroyObject(session, pkcs11.ObjectHandle(2))
	mockTokenCtx.EXPECT().DestroyObject(session, pkcs11.ObjectHandle(3))
	mockTokenCtx.EXPECT().DestroyObject(session, pkcs11.ObjectHandle(4))

	///////////////// START TEST /////////////////

	p11Token, err := newP11Token(mockTokenCtx, tokenLabel, tokenPIN)
	require.Nil(t, err)

	p11Token.DeleteAllExcept(keyLabels[0:2])

}

func TestP11Token_Checksum(t *testing.T) {
	mockCtrl, mockTokenCtx, session := prepMockForLogin(t)
	defer mockCtrl.Finish()

	const keyLabel = "somekey"
	const objectHandle = pkcs11.ObjectHandle(42)
	expected := []byte("this is the encrypted result")

	///////////////// MOCK EXPECTATIONS /////////////////

	mockTokenCtx.EXPECT().FindObjectsInit(session,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel)}).Return(nil)
	mockTokenCtx.EXPECT().FindObjects(session, gomock.Any()).Return([]pkcs11.ObjectHandle{objectHandle}, false, nil)
	mockTokenCtx.EXPECT().FindObjectsFinal(session).Return(nil)

	mockTokenCtx.EXPECT().EncryptInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, make([]byte, 16))}, objectHandle).Return(nil)
	mockTokenCtx.EXPECT().Encrypt(session, make([]byte, 16)).Return(expected, nil)

	///////////////// START TEST /////////////////

	p11Token, err := newP11Token(mockTokenCtx, tokenLabel, tokenPIN)
	require.Nil(t, err)

	result, err := p11Token.Checksum(keyLabel)
	require.Nil(t, err)

	require.Equal(t, expected, result)
}

type attributeMatcher struct {
	required []*pkcs11.Attribute
}

func (m attributeMatcher) Matches(x interface{}) bool {
	attributes := x.([]*pkcs11.Attribute)

outer:
	for _, r := range m.required {
		for _, a := range attributes {
			if a.Type == r.Type {
				if bytes.Equal(a.Value, r.Value) {
					continue outer
				}
				return false
			}
		}
		return false
	}

	return true
}

func (attributeMatcher) String() string {
	return "(various attributes)"
}

func TestP11Token_ImportKey(t *testing.T) {
	mockCtrl, mockTokenCtx, session := prepMockForLogin(t)
	defer mockCtrl.Finish()

	const keyLabel = "somekey"
	const objectHandle = pkcs11.ObjectHandle(42)
	importedKey := []byte("example imported key")

	///////////////// MOCK EXPECTATIONS /////////////////

	mockTokenCtx.EXPECT().CreateObject(session, attributeMatcher{
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, importedKey),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel)}}).Return(objectHandle, nil)

	///////////////// START TEST /////////////////

	p11Token, err := newP11Token(mockTokenCtx, tokenLabel, tokenPIN)
	require.Nil(t, err)

	err = p11Token.ImportKey(importedKey, keyLabel)
	require.Nil(t, err)
}

func TestP11Token_GenerateKey(t *testing.T) {
	mockCtrl, mockTokenCtx, session := prepMockForLogin(t)
	defer mockCtrl.Finish()

	const aesKeyLabel = "testaeskey256"
	const rsaKeyLabel = "testrsakey2048"
	const objectHandle = pkcs11.ObjectHandle(42)

	///////////////// MOCK EXPECTATIONS /////////////////

	mockTokenCtx.EXPECT().GenerateKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, make([]byte, 16))},
		attributeMatcher{
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, aesKeyLabel),
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
			}}).Return(objectHandle, nil)

	mockTokenCtx.EXPECT().GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		attributeMatcher{
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
				pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, rsaKeyLabel),
				pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
			}},
		attributeMatcher{
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
				pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, rsaKeyLabel),
			}}).Return(objectHandle, objectHandle, nil)

	///////////////// START TEST /////////////////

	p11Token, err := newP11Token(mockTokenCtx, tokenLabel, tokenPIN)
	require.Nil(t, err)

	err = p11Token.GenerateKey(aesKeyLabel, "AES", 256)
	require.Nil(t, err)

	err = p11Token.GenerateKey(rsaKeyLabel, "RSA", 2048)
	require.Nil(t, err)
}

func TestP11Token_PrintObjectsWithLabel(t *testing.T) {
	mockCtrl, mockTokenCtx, session := prepMockForLogin(t)
	defer mockCtrl.Finish()

	label := "somelabel"

	handles := []pkcs11.ObjectHandle{1, 2}

	///////////////// MOCK EXPECTATIONS /////////////////

	mockTokenCtx.EXPECT().FindObjectsInit(session,
		attributeMatcher{[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}}).Return(nil)
	call1 := mockTokenCtx.EXPECT().FindObjects(session, gomock.Any()).Return(handles, false, nil)
	mockTokenCtx.EXPECT().FindObjects(session, gomock.Any()).Return(nil, false, nil).After(call1)
	mockTokenCtx.EXPECT().FindObjectsFinal(session)

	// Check we call GetAttributeValue at least once for each handle
	for i := range handles {
		mockTokenCtx.EXPECT().GetAttributeValue(session, handles[i],
			gomock.Any()).MinTimes(1).Return(nil, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID))
	}

	///////////////// START TEST /////////////////

	p11Token, err := newP11Token(mockTokenCtx, tokenLabel, tokenPIN)
	require.Nil(t, err)

	err = p11Token.PrintObjects(&label)
	require.Nil(t, err)
}

func TestP11Token_Finalise(t *testing.T) {
	mockCtrl, mockTokenCtx, _ := prepMockForLogin(t)
	defer mockCtrl.Finish()

	mockTokenCtx.EXPECT().Finalize().Return(nil)
	mockTokenCtx.EXPECT().Destroy()

	p11Token, err := newP11Token(mockTokenCtx, tokenLabel, tokenPIN)
	require.Nil(t, err)

	err = p11Token.Finalise()
	require.Nil(t, err)
}

func TestP11Token_PrintMechanisms(t *testing.T) {
	mockCtrl, mockTokenCtx, _ := prepMockForLogin(t)
	defer mockCtrl.Finish()

	mechs := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil),
		pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, nil), pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, nil)}

	dummyInfo := pkcs11.MechanismInfo{}

	mockTokenCtx.EXPECT().GetMechanismList(slotNumber).Return(mechs, nil)

	// Should be called alphabetically
	gomock.InOrder(
		mockTokenCtx.EXPECT().GetMechanismInfo(slotNumber, []*pkcs11.Mechanism{mechs[1]}).Return(dummyInfo, nil),
		mockTokenCtx.EXPECT().GetMechanismInfo(slotNumber, []*pkcs11.Mechanism{mechs[0]}).Return(dummyInfo, nil),
		mockTokenCtx.EXPECT().GetMechanismInfo(slotNumber, []*pkcs11.Mechanism{mechs[2]}).Return(dummyInfo, nil),
	)

	p11Token, err := newP11Token(mockTokenCtx, tokenLabel, tokenPIN)
	require.Nil(t, err)

	err = p11Token.PrintMechanisms()
	require.NoError(t, err)
}
