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
	"log"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// TokenCtx contains the functions we use from github.com/miekg/pkcs11.
type TokenCtx interface {
	CloseSession(sh pkcs11.SessionHandle) error
	CreateObject(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	Destroy()
	DestroyObject(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error
	Encrypt(sh pkcs11.SessionHandle, message []byte) ([]byte, error)
	EncryptInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error
	Finalize() error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	GenerateKey(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	GenerateKeyPair(sh pkcs11.SessionHandle, mech []*pkcs11.Mechanism, public, private []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error)
	GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error)
	Initialize() error
	Login(sh pkcs11.SessionHandle, userType uint, pin string) error
	OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error)
}

// Token provides a high level interface to a P11 token.
type Token interface {
	// Checksum calculates a checksum value for an AES key. A block of zeroes is encrypted in CBC-mode with a zero IV.
	Checksum(keyLabel string) ([]byte, error)

	// ImportKey imports an AES key and applies a label.
	ImportKey(keyBytes []byte, label string) error

	// DeleteAllExcept deletes all keys on the token except those with a label specified.
	DeleteAllExcept(keyLabels []string) error

	// PrintObjects prints all objects in the token if label is nil, otherwise it prints only the objects with that
	// label
	PrintObjects(label *string) error

	// GenerateKey creates a new RSA or AES key of the given size in the token
	GenerateKey(label, keytype string, keysize int) error

	// Finalise closes the library and unloads it.
	Finalise() error
}

type p11Token struct {
	ctx     TokenCtx
	session pkcs11.SessionHandle
}

func (p *p11Token) DeleteAllExcept(keyLabels []string) error {
	objects, err := p.findAllMatching(nil)
	if err != nil {
		return err
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}

	for _, o := range objects {
		labelExists := true

		template, err = p.ctx.GetAttributeValue(p.session, o, template)
		if err != nil {
			if p11error, ok := err.(pkcs11.Error); ok {
				if p11error == pkcs11.CKR_ATTRIBUTE_TYPE_INVALID {
					// There is no label associated with this key
					log.Println("Failed to get label for key, will delete anyway")
					labelExists = false
				} else {
					return errors.WithMessage(err, "failed to get label")
				}
			} else {
				return errors.WithMessage(err, "failed to get label")
			}

		}

		keep := false

		if labelExists {
			for _, l := range keyLabels {
				if l == string(template[0].Value) {
					keep = true
					break
				}
			}
		}

		if !keep {
			if labelExists {
				log.Printf("Deleting key with label '%s'", string(template[0].Value))
			}

			err = p.ctx.DestroyObject(p.session, o)
			if err != nil {
				return errors.WithMessage(err, "failed to destroy object")
			}
		}
	}

	return nil
}

func (p *p11Token) Finalise() error {
	err := p.ctx.Finalize()
	if err != nil {
		return errors.WithMessage(err, "failed to finalize library")
	}

	p.ctx.Destroy()
	return nil
}

// NewToken connects to a PKCS#11 token and creates a logged in, ready-to-use interface. Call Finalize() on the
// return object when finished.
func NewToken(lib, tokenLabel, pin string) (Token, error) {
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, errors.Errorf("failed to load library %s", lib)
	}

	return newP11Token(ctx, tokenLabel, pin)
}

func newP11Token(ctx TokenCtx, tokenLabel, pin string) (Token, error) {
	err := ctx.Initialize()
	if err != nil {
		return nil, err
	}

	session, err := openUserSession(ctx, tokenLabel, pin)
	return &p11Token{
		ctx:     ctx,
		session: session,
	}, err
}

func (p *p11Token) Checksum(keyLabel string) (checksum []byte, err error) {
	var obj pkcs11.ObjectHandle
	obj, err = p.findKeyByLabel(keyLabel)
	if err != nil {
		return
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, make([]byte, 16))}

	err = p.ctx.EncryptInit(p.session, mech, obj)
	if err != nil {
		return
	}

	checksum, err = p.ctx.Encrypt(p.session, make([]byte, 16))
	return
}

func (p *p11Token) findKeyByLabel(label string) (obj pkcs11.ObjectHandle, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	err = p.ctx.FindObjectsInit(p.session, template)
	if err != nil {
		return
	}

	var objects []pkcs11.ObjectHandle
	objects, _, err = p.ctx.FindObjects(p.session, 1)

	if len(objects) != 1 {
		err = errors.Errorf("no key with label '%s'", label)
		return
	}

	obj = objects[0]

	err = p.ctx.FindObjectsFinal(p.session)
	return
}

func (p *p11Token) ImportKey(keyBytes []byte, label string) error {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, keyBytes),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
    pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	_, err := p.ctx.CreateObject(p.session, template)
	return err
}

// openP11Session loads the P11 library and creates a logged in session
func openUserSession(ctx TokenCtx, tokenLabel, pin string) (session pkcs11.SessionHandle, err error) {
	var slot uint
	slot, err = findSlotWithToken(ctx, tokenLabel)
	if err != nil {
		return
	}

	session, err = ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return
	}

	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	return
}

// findSlotWithToken returns the (first) slot id containing the specific token. If the token is not found an
// error is returned.
func findSlotWithToken(ctx TokenCtx, label string) (slot uint, err error) {
	var slots []uint
	slots, err = ctx.GetSlotList(true)
	if err != nil {
		return
	}

	for _, slot = range slots {
		var info pkcs11.TokenInfo
		info, err = ctx.GetTokenInfo(slot)
		if err != nil {
			return
		}

		if info.Label == label {
			return
		}
	}

	err = errors.Errorf("cannot find token %s", label)
	return
}

func (p *p11Token) findAllMatching(template []*pkcs11.Attribute) (objects []pkcs11.ObjectHandle, err error) {
	const batchSize = 20

	err = p.ctx.FindObjectsInit(p.session, template)
	if err != nil {
		return
	}

	var res []pkcs11.ObjectHandle
	for {
		// The 'more' return value is broken, don't use
		res, _, err = p.ctx.FindObjects(p.session, batchSize)
		if err != nil {
			err = errors.WithMessage(err, "failed to search")
			return
		}

		if len(res) == 0 {
			log.Printf("Found %d objects on token", len(objects))
			break
		}

		objects = append(objects, res...)
	}

	err = p.ctx.FindObjectsFinal(p.session)
	return
}

func (p *p11Token) PrintObjects(label *string) error {
	var template []*pkcs11.Attribute
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, *label))
	}

	objects, err := p.findAllMatching(template)
	if err != nil {
		return err
	}

	for i, o := range objects {
		err := printObject(p.ctx, p.session, o, i+1)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *p11Token) GenerateKey(label, keytype string, keysize int) error {

	validRSASize := []int{1024, 2048, 3072, 4096}
	validAESSize := []int{128, 192, 256}
	validKeyTypes := []string{"RSA", "AES"}

	if (isValidKeyType(validKeyTypes, keytype)) {
		switch keytype {
		case "RSA":
			if (isValidSize(validRSASize, keysize)) {
				return p.GenerateRSAKey(label, keysize)
			} else {
				return errors.Errorf("Invalid RSA key size: %d", keysize)
			}
		case "AES":
			if (isValidSize(validAESSize, keysize)) {
				return p.GenerateAESKey(label, keysize)
			} else {
				return errors.Errorf("Invalid AES key size: %d", keysize)
			}
		}
	} else {
		return errors.Errorf("Invalid key type: %s", keytype)
	}


	return nil
}

func (p *p11Token) GenerateAESKey(label string, keysize int) error {

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keysize/8),
	}

	_, err := p.ctx.GenerateKey(p.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, make([]byte, 16))},
		privateKeyTemplate)

	if err != nil {
		return err
	}

	log.Printf("Key \"%s\" generated on token", label)

	return nil
}

func (p *p11Token) GenerateRSAKey(label string, keysize int) error {

	pubLabel := label + "pub"
	prvLabel := label + "prv"

	log.Print("Enter GenerateRSAKey" )
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, pubLabel),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keysize),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvLabel),
	}

	log.Print("Set attributes" )
	_, _,  err := p.ctx.GenerateKeyPair(p.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	log.Print("Called GenerateKeyPair" )

	if err != nil {
		return err
	}

	log.Printf("Keypair \"%s\" and \"%s\" generated on token", pubLabel, prvLabel)

	return nil
}

func isValidSize(sizes []int, in int) bool {
	for _, n := range sizes {
		if in == n {
			return true
		}
	}
	return false
}

func isValidKeyType(types []string, in string) bool {
	for _, n := range types {
		if in == n {
			return true
		}
	}
	return false
}
