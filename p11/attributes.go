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
	"fmt"
	"strconv"

	"encoding/binary"

	"github.com/miekg/pkcs11"
)

// toStrFunc implementations know how to convert an attribute value to a string
type toStrFunc func(value []byte) string

// AttributeInfo contains information about how to print/display an attribute
type AttributeInfo struct {
	aType     uint
	converter toStrFunc
	name      string
}

func printObject(ctx TokenCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, objNum int) error {
	fmt.Printf("[Object %d]\n", objNum)

	for _, attr := range attributeInfo {

		template := []*pkcs11.Attribute{{attr.aType, nil}}
		template, err := ctx.GetAttributeValue(session, object, template)

		if p11error, ok := err.(pkcs11.Error); ok {
			switch p11error {
			case pkcs11.CKR_ATTRIBUTE_SENSITIVE:
				printWithLabel(attr.name, "<sensitive>")
				continue
			case pkcs11.CKR_ATTRIBUTE_TYPE_INVALID:
				continue
			default:
				// Do nothing, will pick up below
				break
			}
		}

		if err != nil {
			// some other error
			return err
		}

		printWithLabel(attr.name, attr.converter(template[0].Value))
	}

	fmt.Println()
	return nil
}

func printWithLabel(label, value string) {
	fmt.Printf("  %s: %s\n", label, value)
}

var attributeInfo = []AttributeInfo{
	{pkcs11.CKA_CLASS, classToStr, "CKA_CLASS"},
	{pkcs11.CKA_TOKEN, boolToStr, "CKA_TOKEN"},
	{pkcs11.CKA_PRIVATE, boolToStr, "CKA_PRIVATE"},
	{pkcs11.CKA_LABEL, stringToStr, "CKA_LABEL"},
	{pkcs11.CKA_APPLICATION, stringToStr, "CKA_APPLICATION"},
	{pkcs11.CKA_VALUE, bytesToStr, "CKA_VALUE"},
	{pkcs11.CKA_OBJECT_ID, bytesToStr, "CKA_OBJECT_ID"},
	{pkcs11.CKA_CERTIFICATE_TYPE, ulongToStr, "CKA_CERTIFICATE_TYPE"}, // could improve
	{pkcs11.CKA_ISSUER, bytesToStr, "CKA_ISSUER"},
	{pkcs11.CKA_SERIAL_NUMBER, bytesToStr, "CKA_SERIAL_NUMBER"},
	{pkcs11.CKA_AC_ISSUER, bytesToStr, "CKA_AC_ISSUER"},
	{pkcs11.CKA_OWNER, bytesToStr, "CKA_OWNER"},
	{pkcs11.CKA_ATTR_TYPES, bytesToStr, "CKA_ATTR_TYPES"},
	{pkcs11.CKA_TRUSTED, boolToStr, "CKA_TRUSTED"},
	{pkcs11.CKA_CERTIFICATE_CATEGORY, ulongToStr, "CKA_CERTIFICATE_CATEGORY"},           // could improve
	{pkcs11.CKA_JAVA_MIDP_SECURITY_DOMAIN, ulongToStr, "CKA_JAVA_MIDP_SECURITY_DOMAIN"}, // could improve
	{pkcs11.CKA_URL, stringToStr, "CKA_URL"},
	{pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY, bytesToStr, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY"},
	{pkcs11.CKA_HASH_OF_ISSUER_PUBLIC_KEY, bytesToStr, "CKA_HASH_OF_ISSUER_PUBLIC_KEY"},
	{pkcs11.CKA_NAME_HASH_ALGORITHM, mechToStr, "CKA_NAME_HASH_ALGORITHM"},
	{pkcs11.CKA_CHECK_VALUE, bytesToStr, "CKA_CHECK_VALUE"},
	{pkcs11.CKA_KEY_TYPE, keyTypeToStr, "CKA_KEY_TYPE"},
	{pkcs11.CKA_SUBJECT, bytesToStr, "CKA_SUBJECT"},
	{pkcs11.CKA_ID, idToStr, "CKA_ID"},
	{pkcs11.CKA_SENSITIVE, boolToStr, "CKA_SENSITIVE"},
	{pkcs11.CKA_ENCRYPT, boolToStr, "CKA_ENCRYPT"},
	{pkcs11.CKA_DECRYPT, boolToStr, "CKA_DECRYPT"},
	{pkcs11.CKA_WRAP, boolToStr, "CKA_WRAP"},
	{pkcs11.CKA_UNWRAP, boolToStr, "CKA_UNWRAP"},
	{pkcs11.CKA_SIGN, boolToStr, "CKA_SIGN"},
	{pkcs11.CKA_SIGN_RECOVER, boolToStr, "CKA_SIGN_RECOVER"},
	{pkcs11.CKA_VERIFY, boolToStr, "CKA_VERIFY"},
	{pkcs11.CKA_VERIFY_RECOVER, boolToStr, "CKA_VERIFY_RECOVER"},
	{pkcs11.CKA_DERIVE, boolToStr, "CKA_DERIVE"},
	{pkcs11.CKA_START_DATE, dateToStr, "CKA_START_DATE"},
	{pkcs11.CKA_END_DATE, dateToStr, "CKA_END_DATE"},
	{pkcs11.CKA_MODULUS, bytesToStr, "CKA_MODULUS"},
	{pkcs11.CKA_MODULUS_BITS, ulongToStr, "CKA_MODULUS_BITS"},
	{pkcs11.CKA_PUBLIC_EXPONENT, bytesToStr, "CKA_PUBLIC_EXPONENT"},
	{pkcs11.CKA_PRIVATE_EXPONENT, bytesToStr, "CKA_PRIVATE_EXPONENT"},
	{pkcs11.CKA_PRIME_1, bytesToStr, "CKA_PRIME_1"},
	{pkcs11.CKA_PRIME_2, bytesToStr, "CKA_PRIME_2"},
	{pkcs11.CKA_EXPONENT_1, bytesToStr, "CKA_EXPONENT_1"},
	{pkcs11.CKA_EXPONENT_2, bytesToStr, "CKA_EXPONENT_2"},
	{pkcs11.CKA_COEFFICIENT, bytesToStr, "CKA_COEFFICIENT"},
	{pkcs11.CKA_PUBLIC_KEY_INFO, bytesToStr, "CKA_PUBLIC_KEY_INFO"},
	{pkcs11.CKA_PRIME, bytesToStr, "CKA_PRIME"},
	{pkcs11.CKA_SUBPRIME, bytesToStr, "CKA_SUBPRIME"},
	{pkcs11.CKA_BASE, bytesToStr, "CKA_BASE"},
	{pkcs11.CKA_PRIME_BITS, ulongToStr, "CKA_PRIME_BITS"},
	{pkcs11.CKA_SUBPRIME_BITS, ulongToStr, "CKA_SUBPRIME_BITS"},
	{pkcs11.CKA_SUB_PRIME_BITS, ulongToStr, "CKA_SUB_PRIME_BITS"},
	{pkcs11.CKA_VALUE_BITS, ulongToStr, "CKA_VALUE_BITS"},
	{pkcs11.CKA_VALUE_LEN, ulongToStr, "CKA_VALUE_LEN"},
	{pkcs11.CKA_EXTRACTABLE, boolToStr, "CKA_EXTRACTABLE"},
	{pkcs11.CKA_LOCAL, boolToStr, "CKA_LOCAL"},
	{pkcs11.CKA_NEVER_EXTRACTABLE, boolToStr, "CKA_NEVER_EXTRACTABLE"},
	{pkcs11.CKA_ALWAYS_SENSITIVE, boolToStr, "CKA_ALWAYS_SENSITIVE"},
	{pkcs11.CKA_KEY_GEN_MECHANISM, mechToStr, "CKA_KEY_GEN_MECHANISM"},
	{pkcs11.CKA_MODIFIABLE, boolToStr, "CKA_MODIFIABLE"},
	{pkcs11.CKA_COPYABLE, boolToStr, "CKA_COPYABLE"},
	{pkcs11.CKA_DESTROYABLE, boolToStr, "CKA_DESTROYABLE"},
	{pkcs11.CKA_EC_PARAMS, bytesToStr, "CKA_EC_PARAMS"},
	{pkcs11.CKA_EC_POINT, bytesToStr, "CKA_EC_POINT"},
	{pkcs11.CKA_SECONDARY_AUTH, unsupportedToStr, "CKA_SECONDARY_AUTH"}, // deprecated, not sure how to print
	{pkcs11.CKA_AUTH_PIN_FLAGS, unsupportedToStr, "CKA_AUTH_PIN_FLAGS"}, // deprecated, not sure how to print
	{pkcs11.CKA_ALWAYS_AUTHENTICATE, boolToStr, "CKA_ALWAYS_AUTHENTICATE"},
	{pkcs11.CKA_WRAP_WITH_TRUSTED, boolToStr, "CKA_WRAP_WITH_TRUSTED"},
	{pkcs11.CKA_WRAP_TEMPLATE, unsupportedToStr, "CKA_WRAP_TEMPLATE"},     // no support for templates
	{pkcs11.CKA_UNWRAP_TEMPLATE, unsupportedToStr, "CKA_UNWRAP_TEMPLATE"}, // no support for templates
	{pkcs11.CKA_OTP_FORMAT, ulongToStr, "CKA_OTP_FORMAT"},                 // could improve (CK_OTP_FORMAT_DECIMAL etc.)
	{pkcs11.CKA_OTP_LENGTH, ulongToStr, "CKA_OTP_LENGTH"},
	{pkcs11.CKA_OTP_TIME_INTERVAL, ulongToStr, "CKA_OTP_TIME_INTERVAL"},
	{pkcs11.CKA_OTP_USER_FRIENDLY_MODE, boolToStr, "CKA_OTP_USER_FRIENDLY_MODE"},
	{pkcs11.CKA_OTP_CHALLENGE_REQUIREMENT, ulongToStr, "CKA_OTP_CHALLENGE_REQUIREMENT"}, // could be improved
	{pkcs11.CKA_OTP_TIME_REQUIREMENT, ulongToStr, "CKA_OTP_TIME_REQUIREMENT"},           // could be improved
	{pkcs11.CKA_OTP_COUNTER_REQUIREMENT, ulongToStr, "CKA_OTP_COUNTER_REQUIREMENT"},     // could be improved
	{pkcs11.CKA_OTP_PIN_REQUIREMENT, ulongToStr, "CKA_OTP_PIN_REQUIREMENT"},             // could be improved
	{pkcs11.CKA_OTP_COUNTER, bytesToStr, "CKA_OTP_COUNTER"},
	{pkcs11.CKA_OTP_TIME, stringToStr, "CKA_OTP_TIME"},
	{pkcs11.CKA_OTP_USER_IDENTIFIER, stringToStr, "CKA_OTP_USER_IDENTIFIER"},
	{pkcs11.CKA_OTP_SERVICE_IDENTIFIER, stringToStr, "CKA_OTP_SERVICE_IDENTIFIER"},
	{pkcs11.CKA_OTP_SERVICE_LOGO, bytesToStr, "CKA_OTP_SERVICE_LOGO"},
	{pkcs11.CKA_OTP_SERVICE_LOGO_TYPE, stringToStr, "CKA_OTP_SERVICE_LOGO_TYPE"},
	{pkcs11.CKA_GOSTR3410_PARAMS, bytesToStr, "CKA_GOSTR3410_PARAMS"},
	{pkcs11.CKA_GOSTR3411_PARAMS, bytesToStr, "CKA_GOSTR3411_PARAMS"},
	{pkcs11.CKA_GOST28147_PARAMS, bytesToStr, "CKA_GOST28147_PARAMS"},
	{pkcs11.CKA_HW_FEATURE_TYPE, ulongToStr, "CKA_HW_FEATURE_TYPE"}, // could be improved (CK_HW_FEATURE_TYPE)
	{pkcs11.CKA_RESET_ON_INIT, boolToStr, "CKA_RESET_ON_INIT"},
	{pkcs11.CKA_HAS_RESET, boolToStr, "CKA_HAS_RESET"},
	{pkcs11.CKA_PIXEL_X, ulongToStr, "CKA_PIXEL_X"},
	{pkcs11.CKA_PIXEL_Y, ulongToStr, "CKA_PIXEL_Y"},
	{pkcs11.CKA_RESOLUTION, ulongToStr, "CKA_RESOLUTION"},
	{pkcs11.CKA_CHAR_ROWS, ulongToStr, "CKA_CHAR_ROWS"},
	{pkcs11.CKA_CHAR_COLUMNS, ulongToStr, "CKA_CHAR_COLUMNS"},
	{pkcs11.CKA_COLOR, boolToStr, "CKA_COLOR"},
	{pkcs11.CKA_BITS_PER_PIXEL, ulongToStr, "CKA_BITS_PER_PIXEL"},
	{pkcs11.CKA_CHAR_SETS, stringToStr, "CKA_CHAR_SETS"},
	{pkcs11.CKA_ENCODING_METHODS, stringToStr, "CKA_ENCODING_METHODS"},
	{pkcs11.CKA_MIME_TYPES, stringToStr, "CKA_MIME_TYPES"},
	{pkcs11.CKA_MECHANISM_TYPE, mechToStr, "CKA_MECHANISM_TYPE"},
	{pkcs11.CKA_REQUIRED_CMS_ATTRIBUTES, bytesToStr, "CKA_REQUIRED_CMS_ATTRIBUTES"},
	{pkcs11.CKA_DEFAULT_CMS_ATTRIBUTES, bytesToStr, "CKA_DEFAULT_CMS_ATTRIBUTES"},
	{pkcs11.CKA_SUPPORTED_CMS_ATTRIBUTES, bytesToStr, "CKA_SUPPORTED_CMS_ATTRIBUTES"},
	{pkcs11.CKA_ALLOWED_MECHANISMS, mechArrayToStr, "CKA_ALLOWED_MECHANISMS"},
	{pkcs11.CKA_VENDOR_DEFINED, unsupportedToStr, "CKA_VENDOR_DEFINED"},
}

func boolToStr(value []byte) string {
	bValue := 1 == value[0]
	return strconv.FormatBool(bValue)
}

func ulongToStr(value []byte) string {
	iValue := readAttributeAsULong(value)
	return strconv.FormatUint(uint64(iValue), 10)
}

func bytesToStr(value []byte) string {
	return fmt.Sprintf("%x (hex)", value)
}

func stringToStr(value []byte) string {
	return string(value)
}

func idToStr(value []byte) string {
	// See if it's printable
	printable := true
	for _, c := range value {
		if c < 0x20 {
			printable = false
			break
		}
	}

	if printable {
		return stringToStr(value)
	}

	return bytesToStr(value)
}

func getUnknownString(value []byte) string {
	return fmt.Sprintf("Unknown: 0x%X", value)
}

func unknownToStr(value []byte) string {
	return getUnknownString(value)
}

func mechToStr(value []byte) string {
	val := readAttributeAsULong(value)
	str, err := mechToString(uint(val))
	if err == nil {
		return str
	} else {
		return unknownToStr(value)
	}
}

func mechArrayToStr(value []byte) string {
	var mechs []string

	for offset := 0; offset < len(value); offset += 4 {
		val := readSliceAsULong(value[offset:])
		str, err := mechToString(uint(val))
		if err != nil {
			str = getUnknownString(value[offset : offset+4])
		}
		mechs = append(mechs, str)
	}

	return fmt.Sprintf("%v", mechs)
}

func dateToStr(value []byte) string {
	return fmt.Sprintf("%s-%s-%s", string(value[:4]), string(value[4:6]), string(value[6:]))
}

func classToStr(value []byte) string {
	class := readAttributeAsULong(value)
	str, err := classToString(uint(class))
	if err == nil {
		return str
	}

	return unknownToStr(value)
}

func keyTypeToStr(value []byte) string {
	keyType := readAttributeAsULong(value)
	str, err := keyTypeToString(uint(keyType))

	if err == nil {
		return str
	}

	return unknownToStr(value)
}

func unsupportedToStr(_ []byte) string {
	return "<not yet supported to print>"
}

// readSliceAsULong reads the first 4 bytes out of b
func readSliceAsULong(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

func readAttributeAsULong(value []byte) uint32 {
	return readSliceAsULong(value)
}
