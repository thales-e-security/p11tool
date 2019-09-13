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
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

func classToString(class uint) (res string, err error) {
	switch class {
	case pkcs11.CKO_DATA:
		res = "CKO_DATA"
	case pkcs11.CKO_CERTIFICATE:
		res = "CKO_CERTIFICATE"
	case pkcs11.CKO_PUBLIC_KEY:
		res = "CKO_PUBLIC_KEY"
	case pkcs11.CKO_PRIVATE_KEY:
		res = "CKO_PRIVATE_KEY"
	case pkcs11.CKO_SECRET_KEY:
		res = "CKO_SECRET_KEY"
	case pkcs11.CKO_HW_FEATURE:
		res = "CKO_HW_FEATURE"
	case pkcs11.CKO_DOMAIN_PARAMETERS:
		res = "CKO_DOMAIN_PARAMETERS"
	case pkcs11.CKO_MECHANISM:
		res = "CKO_MECHANISM"
	case pkcs11.CKO_OTP_KEY:
		res = "CKO_OTP_KEY"
	case pkcs11.CKO_VENDOR_DEFINED:
		res = "CKO_VENDOR_DEFINED"
	default:
		err = errors.New("Unrecognised")
	}
	return
}

func keyTypeToString(keyType uint) (res string, err error) {
	switch keyType {
	case pkcs11.CKK_RSA:
		res = "CKK_RSA"
	case pkcs11.CKK_DSA:
		res = "CKK_DSA"
	case pkcs11.CKK_DH:
		res = "CKK_DH"
	case pkcs11.CKK_EC:
		res = "CKK_EC"
	case pkcs11.CKK_X9_42_DH:
		res = "CKK_X9_42_DH"
	case pkcs11.CKK_KEA:
		res = "CKK_KEA"
	case pkcs11.CKK_GENERIC_SECRET:
		res = "CKK_GENERIC_SECRET"
	case pkcs11.CKK_RC2:
		res = "CKK_RC2"
	case pkcs11.CKK_RC4:
		res = "CKK_RC4"
	case pkcs11.CKK_DES:
		res = "CKK_DES"
	case pkcs11.CKK_DES2:
		res = "CKK_DES2"
	case pkcs11.CKK_DES3:
		res = "CKK_DES3"
	case pkcs11.CKK_CAST:
		res = "CKK_CAST"
	case pkcs11.CKK_CAST3:
		res = "CKK_CAST3"
	case pkcs11.CKK_CAST128:
		res = "CKK_CAST128"
	case pkcs11.CKK_RC5:
		res = "CKK_RC5"
	case pkcs11.CKK_IDEA:
		res = "CKK_IDEA"
	case pkcs11.CKK_SKIPJACK:
		res = "CKK_SKIPJACK"
	case pkcs11.CKK_BATON:
		res = "CKK_BATON"
	case pkcs11.CKK_JUNIPER:
		res = "CKK_JUNIPER"
	case pkcs11.CKK_CDMF:
		res = "CKK_CDMF"
	case pkcs11.CKK_AES:
		res = "CKK_AES"
	case pkcs11.CKK_BLOWFISH:
		res = "CKK_BLOWFISH"
	case pkcs11.CKK_TWOFISH:
		res = "CKK_TWOFISH"
	case pkcs11.CKK_SECURID:
		res = "CKK_SECURID"
	case pkcs11.CKK_HOTP:
		res = "CKK_HOTP"
	case pkcs11.CKK_ACTI:
		res = "CKK_ACTI"
	case pkcs11.CKK_CAMELLIA:
		res = "CKK_CAMELLIA"
	case pkcs11.CKK_ARIA:
		res = "CKK_ARIA"
	case pkcs11.CKK_SHA_1_HMAC:
		res = "CKK_SHA_1_HMAC"
	case pkcs11.CKK_SHA256_HMAC:
		res = "CKK_SHA256_HMAC"
	case pkcs11.CKK_SHA384_HMAC:
		res = "CKK_SHA384_HMAC"
	case pkcs11.CKK_SHA512_HMAC:
		res = "CKK_SHA512_HMAC"
	case pkcs11.CKK_SHA224_HMAC:
		res = "CKK_SHA224_HMAC"
	case pkcs11.CKK_SEED:
		res = "CKK_SEED"
	case pkcs11.CKK_GOSTR3410:
		res = "CKK_GOSTR3410"
	case pkcs11.CKK_GOSTR3411:
		res = "CKK_GOSTR3411"
	case pkcs11.CKK_GOST28147:
		res = "CKK_GOST28147"
	case pkcs11.CKK_VENDOR_DEFINED:
		res = "CKK_VENDOR_DEFINED"
	default:
		err = errors.New("Unrecognised")
	}
	return
}

func mechToStringAlways(mechType uint) string {
	res, err := mechToString(mechType)
	if err != nil {
		return fmt.Sprintf("Unknown: %#x", mechType)
	}
	return res
}

func mechToString(mechType uint) (res string, err error) {
	switch mechType {
	case pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN:
		res = "CKM_RSA_PKCS_KEY_PAIR_GEN"
	case pkcs11.CKM_RSA_PKCS:
		res = "CKM_RSA_PKCS"
	case pkcs11.CKM_RSA_9796:
		res = "CKM_RSA_9796"
	case pkcs11.CKM_RSA_X_509:
		res = "CKM_RSA_X_509"
	case pkcs11.CKM_MD2_RSA_PKCS:
		res = "CKM_MD2_RSA_PKCS"
	case pkcs11.CKM_MD5_RSA_PKCS:
		res = "CKM_MD5_RSA_PKCS"
	case pkcs11.CKM_SHA1_RSA_PKCS:
		res = "CKM_SHA1_RSA_PKCS"
	case pkcs11.CKM_RIPEMD128_RSA_PKCS:
		res = "CKM_RIPEMD128_RSA_PKCS"
	case pkcs11.CKM_RIPEMD160_RSA_PKCS:
		res = "CKM_RIPEMD160_RSA_PKCS"
	case pkcs11.CKM_RSA_PKCS_OAEP:
		res = "CKM_RSA_PKCS_OAEP"
	case pkcs11.CKM_RSA_X9_31_KEY_PAIR_GEN:
		res = "CKM_RSA_X9_31_KEY_PAIR_GEN"
	case pkcs11.CKM_RSA_X9_31:
		res = "CKM_RSA_X9_31"
	case pkcs11.CKM_SHA1_RSA_X9_31:
		res = "CKM_SHA1_RSA_X9_31"
	case pkcs11.CKM_RSA_PKCS_PSS:
		res = "CKM_RSA_PKCS_PSS"
	case pkcs11.CKM_SHA1_RSA_PKCS_PSS:
		res = "CKM_SHA1_RSA_PKCS_PSS"
	case pkcs11.CKM_DSA_KEY_PAIR_GEN:
		res = "CKM_DSA_KEY_PAIR_GEN"
	case pkcs11.CKM_DSA:
		res = "CKM_DSA"
	case pkcs11.CKM_DSA_SHA1:
		res = "CKM_DSA_SHA1"
	case pkcs11.CKM_DSA_SHA224:
		res = "CKM_DSA_SHA224"
	case pkcs11.CKM_DSA_SHA256:
		res = "CKM_DSA_SHA256"
	case pkcs11.CKM_DSA_SHA384:
		res = "CKM_DSA_SHA384"
	case pkcs11.CKM_DSA_SHA512:
		res = "CKM_DSA_SHA512"
	case pkcs11.CKM_DH_PKCS_KEY_PAIR_GEN:
		res = "CKM_DH_PKCS_KEY_PAIR_GEN"
	case pkcs11.CKM_DH_PKCS_DERIVE:
		res = "CKM_DH_PKCS_DERIVE"
	case pkcs11.CKM_X9_42_DH_KEY_PAIR_GEN:
		res = "CKM_X9_42_DH_KEY_PAIR_GEN"
	case pkcs11.CKM_X9_42_DH_DERIVE:
		res = "CKM_X9_42_DH_DERIVE"
	case pkcs11.CKM_X9_42_DH_HYBRID_DERIVE:
		res = "CKM_X9_42_DH_HYBRID_DERIVE"
	case pkcs11.CKM_X9_42_MQV_DERIVE:
		res = "CKM_X9_42_MQV_DERIVE"
	case pkcs11.CKM_SHA256_RSA_PKCS:
		res = "CKM_SHA256_RSA_PKCS"
	case pkcs11.CKM_SHA384_RSA_PKCS:
		res = "CKM_SHA384_RSA_PKCS"
	case pkcs11.CKM_SHA512_RSA_PKCS:
		res = "CKM_SHA512_RSA_PKCS"
	case pkcs11.CKM_SHA256_RSA_PKCS_PSS:
		res = "CKM_SHA256_RSA_PKCS_PSS"
	case pkcs11.CKM_SHA384_RSA_PKCS_PSS:
		res = "CKM_SHA384_RSA_PKCS_PSS"
	case pkcs11.CKM_SHA512_RSA_PKCS_PSS:
		res = "CKM_SHA512_RSA_PKCS_PSS"
	case pkcs11.CKM_SHA224_RSA_PKCS:
		res = "CKM_SHA224_RSA_PKCS"
	case pkcs11.CKM_SHA224_RSA_PKCS_PSS:
		res = "CKM_SHA224_RSA_PKCS_PSS"
	case pkcs11.CKM_SHA512_224:
		res = "CKM_SHA512_224"
	case pkcs11.CKM_SHA512_224_HMAC:
		res = "CKM_SHA512_224_HMAC"
	case pkcs11.CKM_SHA512_224_HMAC_GENERAL:
		res = "CKM_SHA512_224_HMAC_GENERAL"
	case pkcs11.CKM_SHA512_224_KEY_DERIVATION:
		res = "CKM_SHA512_224_KEY_DERIVATION"
	case pkcs11.CKM_SHA512_256:
		res = "CKM_SHA512_256"
	case pkcs11.CKM_SHA512_256_HMAC:
		res = "CKM_SHA512_256_HMAC"
	case pkcs11.CKM_SHA512_256_HMAC_GENERAL:
		res = "CKM_SHA512_256_HMAC_GENERAL"
	case pkcs11.CKM_SHA512_256_KEY_DERIVATION:
		res = "CKM_SHA512_256_KEY_DERIVATION"
	case pkcs11.CKM_SHA512_T:
		res = "CKM_SHA512_T"
	case pkcs11.CKM_SHA512_T_HMAC:
		res = "CKM_SHA512_T_HMAC"
	case pkcs11.CKM_SHA512_T_HMAC_GENERAL:
		res = "CKM_SHA512_T_HMAC_GENERAL"
	case pkcs11.CKM_SHA512_T_KEY_DERIVATION:
		res = "CKM_SHA512_T_KEY_DERIVATION"
	case pkcs11.CKM_RC2_KEY_GEN:
		res = "CKM_RC2_KEY_GEN"
	case pkcs11.CKM_RC2_ECB:
		res = "CKM_RC2_ECB"
	case pkcs11.CKM_RC2_CBC:
		res = "CKM_RC2_CBC"
	case pkcs11.CKM_RC2_MAC:
		res = "CKM_RC2_MAC"
	case pkcs11.CKM_RC2_MAC_GENERAL:
		res = "CKM_RC2_MAC_GENERAL"
	case pkcs11.CKM_RC2_CBC_PAD:
		res = "CKM_RC2_CBC_PAD"
	case pkcs11.CKM_RC4_KEY_GEN:
		res = "CKM_RC4_KEY_GEN"
	case pkcs11.CKM_RC4:
		res = "CKM_RC4"
	case pkcs11.CKM_DES_KEY_GEN:
		res = "CKM_DES_KEY_GEN"
	case pkcs11.CKM_DES_ECB:
		res = "CKM_DES_ECB"
	case pkcs11.CKM_DES_CBC:
		res = "CKM_DES_CBC"
	case pkcs11.CKM_DES_MAC:
		res = "CKM_DES_MAC"
	case pkcs11.CKM_DES_MAC_GENERAL:
		res = "CKM_DES_MAC_GENERAL"
	case pkcs11.CKM_DES_CBC_PAD:
		res = "CKM_DES_CBC_PAD"
	case pkcs11.CKM_DES2_KEY_GEN:
		res = "CKM_DES2_KEY_GEN"
	case pkcs11.CKM_DES3_KEY_GEN:
		res = "CKM_DES3_KEY_GEN"
	case pkcs11.CKM_DES3_ECB:
		res = "CKM_DES3_ECB"
	case pkcs11.CKM_DES3_CBC:
		res = "CKM_DES3_CBC"
	case pkcs11.CKM_DES3_MAC:
		res = "CKM_DES3_MAC"
	case pkcs11.CKM_DES3_MAC_GENERAL:
		res = "CKM_DES3_MAC_GENERAL"
	case pkcs11.CKM_DES3_CBC_PAD:
		res = "CKM_DES3_CBC_PAD"
	case pkcs11.CKM_DES3_CMAC_GENERAL:
		res = "CKM_DES3_CMAC_GENERAL"
	case pkcs11.CKM_DES3_CMAC:
		res = "CKM_DES3_CMAC"
	case pkcs11.CKM_CDMF_KEY_GEN:
		res = "CKM_CDMF_KEY_GEN"
	case pkcs11.CKM_CDMF_ECB:
		res = "CKM_CDMF_ECB"
	case pkcs11.CKM_CDMF_CBC:
		res = "CKM_CDMF_CBC"
	case pkcs11.CKM_CDMF_MAC:
		res = "CKM_CDMF_MAC"
	case pkcs11.CKM_CDMF_MAC_GENERAL:
		res = "CKM_CDMF_MAC_GENERAL"
	case pkcs11.CKM_CDMF_CBC_PAD:
		res = "CKM_CDMF_CBC_PAD"
	case pkcs11.CKM_DES_OFB64:
		res = "CKM_DES_OFB64"
	case pkcs11.CKM_DES_OFB8:
		res = "CKM_DES_OFB8"
	case pkcs11.CKM_DES_CFB64:
		res = "CKM_DES_CFB64"
	case pkcs11.CKM_DES_CFB8:
		res = "CKM_DES_CFB8"
	case pkcs11.CKM_MD2:
		res = "CKM_MD2"
	case pkcs11.CKM_MD2_HMAC:
		res = "CKM_MD2_HMAC"
	case pkcs11.CKM_MD2_HMAC_GENERAL:
		res = "CKM_MD2_HMAC_GENERAL"
	case pkcs11.CKM_MD5:
		res = "CKM_MD5"
	case pkcs11.CKM_MD5_HMAC:
		res = "CKM_MD5_HMAC"
	case pkcs11.CKM_MD5_HMAC_GENERAL:
		res = "CKM_MD5_HMAC_GENERAL"
	case pkcs11.CKM_SHA_1:
		res = "CKM_SHA_1"
	case pkcs11.CKM_SHA_1_HMAC:
		res = "CKM_SHA_1_HMAC"
	case pkcs11.CKM_SHA_1_HMAC_GENERAL:
		res = "CKM_SHA_1_HMAC_GENERAL"
	case pkcs11.CKM_RIPEMD128:
		res = "CKM_RIPEMD128"
	case pkcs11.CKM_RIPEMD128_HMAC:
		res = "CKM_RIPEMD128_HMAC"
	case pkcs11.CKM_RIPEMD128_HMAC_GENERAL:
		res = "CKM_RIPEMD128_HMAC_GENERAL"
	case pkcs11.CKM_RIPEMD160:
		res = "CKM_RIPEMD160"
	case pkcs11.CKM_RIPEMD160_HMAC:
		res = "CKM_RIPEMD160_HMAC"
	case pkcs11.CKM_RIPEMD160_HMAC_GENERAL:
		res = "CKM_RIPEMD160_HMAC_GENERAL"
	case pkcs11.CKM_SHA256:
		res = "CKM_SHA256"
	case pkcs11.CKM_SHA256_HMAC:
		res = "CKM_SHA256_HMAC"
	case pkcs11.CKM_SHA256_HMAC_GENERAL:
		res = "CKM_SHA256_HMAC_GENERAL"
	case pkcs11.CKM_SHA224:
		res = "CKM_SHA224"
	case pkcs11.CKM_SHA224_HMAC:
		res = "CKM_SHA224_HMAC"
	case pkcs11.CKM_SHA224_HMAC_GENERAL:
		res = "CKM_SHA224_HMAC_GENERAL"
	case pkcs11.CKM_SHA384:
		res = "CKM_SHA384"
	case pkcs11.CKM_SHA384_HMAC:
		res = "CKM_SHA384_HMAC"
	case pkcs11.CKM_SHA384_HMAC_GENERAL:
		res = "CKM_SHA384_HMAC_GENERAL"
	case pkcs11.CKM_SHA512:
		res = "CKM_SHA512"
	case pkcs11.CKM_SHA512_HMAC:
		res = "CKM_SHA512_HMAC"
	case pkcs11.CKM_SHA512_HMAC_GENERAL:
		res = "CKM_SHA512_HMAC_GENERAL"
	case pkcs11.CKM_SECURID_KEY_GEN:
		res = "CKM_SECURID_KEY_GEN"
	case pkcs11.CKM_SECURID:
		res = "CKM_SECURID"
	case pkcs11.CKM_HOTP_KEY_GEN:
		res = "CKM_HOTP_KEY_GEN"
	case pkcs11.CKM_HOTP:
		res = "CKM_HOTP"
	case pkcs11.CKM_ACTI:
		res = "CKM_ACTI"
	case pkcs11.CKM_ACTI_KEY_GEN:
		res = "CKM_ACTI_KEY_GEN"
	case pkcs11.CKM_CAST_KEY_GEN:
		res = "CKM_CAST_KEY_GEN"
	case pkcs11.CKM_CAST_ECB:
		res = "CKM_CAST_ECB"
	case pkcs11.CKM_CAST_CBC:
		res = "CKM_CAST_CBC"
	case pkcs11.CKM_CAST_MAC:
		res = "CKM_CAST_MAC"
	case pkcs11.CKM_CAST_MAC_GENERAL:
		res = "CKM_CAST_MAC_GENERAL"
	case pkcs11.CKM_CAST_CBC_PAD:
		res = "CKM_CAST_CBC_PAD"
	case pkcs11.CKM_CAST3_KEY_GEN:
		res = "CKM_CAST3_KEY_GEN"
	case pkcs11.CKM_CAST3_ECB:
		res = "CKM_CAST3_ECB"
	case pkcs11.CKM_CAST3_CBC:
		res = "CKM_CAST3_CBC"
	case pkcs11.CKM_CAST3_MAC:
		res = "CKM_CAST3_MAC"
	case pkcs11.CKM_CAST3_MAC_GENERAL:
		res = "CKM_CAST3_MAC_GENERAL"
	case pkcs11.CKM_CAST3_CBC_PAD:
		res = "CKM_CAST3_CBC_PAD"
	case pkcs11.CKM_CAST128_KEY_GEN:
		res = "CKM_CAST128_KEY_GEN"
	case pkcs11.CKM_CAST128_ECB:
		res = "CKM_CAST128_ECB"
	case pkcs11.CKM_CAST128_CBC:
		res = "CKM_CAST128_CBC"
	case pkcs11.CKM_CAST128_MAC:
		res = "CKM_CAST128_MAC"
	case pkcs11.CKM_CAST128_MAC_GENERAL:
		res = "CKM_CAST128_MAC_GENERAL"
	case pkcs11.CKM_CAST128_CBC_PAD:
		res = "CKM_CAST128_CBC_PAD"
	case pkcs11.CKM_RC5_KEY_GEN:
		res = "CKM_RC5_KEY_GEN"
	case pkcs11.CKM_RC5_ECB:
		res = "CKM_RC5_ECB"
	case pkcs11.CKM_RC5_CBC:
		res = "CKM_RC5_CBC"
	case pkcs11.CKM_RC5_MAC:
		res = "CKM_RC5_MAC"
	case pkcs11.CKM_RC5_MAC_GENERAL:
		res = "CKM_RC5_MAC_GENERAL"
	case pkcs11.CKM_RC5_CBC_PAD:
		res = "CKM_RC5_CBC_PAD"
	case pkcs11.CKM_IDEA_KEY_GEN:
		res = "CKM_IDEA_KEY_GEN"
	case pkcs11.CKM_IDEA_ECB:
		res = "CKM_IDEA_ECB"
	case pkcs11.CKM_IDEA_CBC:
		res = "CKM_IDEA_CBC"
	case pkcs11.CKM_IDEA_MAC:
		res = "CKM_IDEA_MAC"
	case pkcs11.CKM_IDEA_MAC_GENERAL:
		res = "CKM_IDEA_MAC_GENERAL"
	case pkcs11.CKM_IDEA_CBC_PAD:
		res = "CKM_IDEA_CBC_PAD"
	case pkcs11.CKM_GENERIC_SECRET_KEY_GEN:
		res = "CKM_GENERIC_SECRET_KEY_GEN"
	case pkcs11.CKM_CONCATENATE_BASE_AND_KEY:
		res = "CKM_CONCATENATE_BASE_AND_KEY"
	case pkcs11.CKM_CONCATENATE_BASE_AND_DATA:
		res = "CKM_CONCATENATE_BASE_AND_DATA"
	case pkcs11.CKM_CONCATENATE_DATA_AND_BASE:
		res = "CKM_CONCATENATE_DATA_AND_BASE"
	case pkcs11.CKM_XOR_BASE_AND_DATA:
		res = "CKM_XOR_BASE_AND_DATA"
	case pkcs11.CKM_EXTRACT_KEY_FROM_KEY:
		res = "CKM_EXTRACT_KEY_FROM_KEY"
	case pkcs11.CKM_SSL3_PRE_MASTER_KEY_GEN:
		res = "CKM_SSL3_PRE_MASTER_KEY_GEN"
	case pkcs11.CKM_SSL3_MASTER_KEY_DERIVE:
		res = "CKM_SSL3_MASTER_KEY_DERIVE"
	case pkcs11.CKM_SSL3_KEY_AND_MAC_DERIVE:
		res = "CKM_SSL3_KEY_AND_MAC_DERIVE"
	case pkcs11.CKM_SSL3_MASTER_KEY_DERIVE_DH:
		res = "CKM_SSL3_MASTER_KEY_DERIVE_DH"
	case pkcs11.CKM_TLS_PRE_MASTER_KEY_GEN:
		res = "CKM_TLS_PRE_MASTER_KEY_GEN"
	case pkcs11.CKM_TLS_MASTER_KEY_DERIVE:
		res = "CKM_TLS_MASTER_KEY_DERIVE"
	case pkcs11.CKM_TLS_KEY_AND_MAC_DERIVE:
		res = "CKM_TLS_KEY_AND_MAC_DERIVE"
	case pkcs11.CKM_TLS_MASTER_KEY_DERIVE_DH:
		res = "CKM_TLS_MASTER_KEY_DERIVE_DH"
	case pkcs11.CKM_TLS_PRF:
		res = "CKM_TLS_PRF"
	case pkcs11.CKM_SSL3_MD5_MAC:
		res = "CKM_SSL3_MD5_MAC"
	case pkcs11.CKM_SSL3_SHA1_MAC:
		res = "CKM_SSL3_SHA1_MAC"
	case pkcs11.CKM_MD5_KEY_DERIVATION:
		res = "CKM_MD5_KEY_DERIVATION"
	case pkcs11.CKM_MD2_KEY_DERIVATION:
		res = "CKM_MD2_KEY_DERIVATION"
	case pkcs11.CKM_SHA1_KEY_DERIVATION:
		res = "CKM_SHA1_KEY_DERIVATION"
	case pkcs11.CKM_SHA256_KEY_DERIVATION:
		res = "CKM_SHA256_KEY_DERIVATION"
	case pkcs11.CKM_SHA384_KEY_DERIVATION:
		res = "CKM_SHA384_KEY_DERIVATION"
	case pkcs11.CKM_SHA512_KEY_DERIVATION:
		res = "CKM_SHA512_KEY_DERIVATION"
	case pkcs11.CKM_SHA224_KEY_DERIVATION:
		res = "CKM_SHA224_KEY_DERIVATION"
	case pkcs11.CKM_PBE_MD2_DES_CBC:
		res = "CKM_PBE_MD2_DES_CBC"
	case pkcs11.CKM_PBE_MD5_DES_CBC:
		res = "CKM_PBE_MD5_DES_CBC"
	case pkcs11.CKM_PBE_MD5_CAST_CBC:
		res = "CKM_PBE_MD5_CAST_CBC"
	case pkcs11.CKM_PBE_MD5_CAST3_CBC:
		res = "CKM_PBE_MD5_CAST3_CBC"
	case pkcs11.CKM_PBE_MD5_CAST128_CBC:
		res = "CKM_PBE_MD5_CAST128_CBC"
	case pkcs11.CKM_PBE_SHA1_CAST128_CBC:
		res = "CKM_PBE_SHA1_CAST128_CBC"
	case pkcs11.CKM_PBE_SHA1_RC4_128:
		res = "CKM_PBE_SHA1_RC4_128"
	case pkcs11.CKM_PBE_SHA1_RC4_40:
		res = "CKM_PBE_SHA1_RC4_40"
	case pkcs11.CKM_PBE_SHA1_DES3_EDE_CBC:
		res = "CKM_PBE_SHA1_DES3_EDE_CBC"
	case pkcs11.CKM_PBE_SHA1_DES2_EDE_CBC:
		res = "CKM_PBE_SHA1_DES2_EDE_CBC"
	case pkcs11.CKM_PBE_SHA1_RC2_128_CBC:
		res = "CKM_PBE_SHA1_RC2_128_CBC"
	case pkcs11.CKM_PBE_SHA1_RC2_40_CBC:
		res = "CKM_PBE_SHA1_RC2_40_CBC"
	case pkcs11.CKM_PKCS5_PBKD2:
		res = "CKM_PKCS5_PBKD2"
	case pkcs11.CKM_PBA_SHA1_WITH_SHA1_HMAC:
		res = "CKM_PBA_SHA1_WITH_SHA1_HMAC"
	case pkcs11.CKM_WTLS_PRE_MASTER_KEY_GEN:
		res = "CKM_WTLS_PRE_MASTER_KEY_GEN"
	case pkcs11.CKM_WTLS_MASTER_KEY_DERIVE:
		res = "CKM_WTLS_MASTER_KEY_DERIVE"
	case pkcs11.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:
		res = "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC"
	case pkcs11.CKM_WTLS_PRF:
		res = "CKM_WTLS_PRF"
	case pkcs11.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:
		res = "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE"
	case pkcs11.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:
		res = "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE"
	case pkcs11.CKM_TLS10_MAC_SERVER:
		res = "CKM_TLS10_MAC_SERVER"
	case pkcs11.CKM_TLS10_MAC_CLIENT:
		res = "CKM_TLS10_MAC_CLIENT"
	case pkcs11.CKM_TLS12_MAC:
		res = "CKM_TLS12_MAC"
	case pkcs11.CKM_TLS12_KDF:
		res = "CKM_TLS12_KDF"
	case pkcs11.CKM_TLS12_MASTER_KEY_DERIVE:
		res = "CKM_TLS12_MASTER_KEY_DERIVE"
	case pkcs11.CKM_TLS12_KEY_AND_MAC_DERIVE:
		res = "CKM_TLS12_KEY_AND_MAC_DERIVE"
	case pkcs11.CKM_TLS12_MASTER_KEY_DERIVE_DH:
		res = "CKM_TLS12_MASTER_KEY_DERIVE_DH"
	case pkcs11.CKM_TLS12_KEY_SAFE_DERIVE:
		res = "CKM_TLS12_KEY_SAFE_DERIVE"
	case pkcs11.CKM_TLS_MAC:
		res = "CKM_TLS_MAC"
	case pkcs11.CKM_TLS_KDF:
		res = "CKM_TLS_KDF"
	case pkcs11.CKM_KEY_WRAP_LYNKS:
		res = "CKM_KEY_WRAP_LYNKS"
	case pkcs11.CKM_KEY_WRAP_SET_OAEP:
		res = "CKM_KEY_WRAP_SET_OAEP"
	case pkcs11.CKM_CMS_SIG:
		res = "CKM_CMS_SIG"
	case pkcs11.CKM_KIP_DERIVE:
		res = "CKM_KIP_DERIVE"
	case pkcs11.CKM_KIP_WRAP:
		res = "CKM_KIP_WRAP"
	case pkcs11.CKM_KIP_MAC:
		res = "CKM_KIP_MAC"
	case pkcs11.CKM_CAMELLIA_KEY_GEN:
		res = "CKM_CAMELLIA_KEY_GEN"
	case pkcs11.CKM_CAMELLIA_ECB:
		res = "CKM_CAMELLIA_ECB"
	case pkcs11.CKM_CAMELLIA_CBC:
		res = "CKM_CAMELLIA_CBC"
	case pkcs11.CKM_CAMELLIA_MAC:
		res = "CKM_CAMELLIA_MAC"
	case pkcs11.CKM_CAMELLIA_MAC_GENERAL:
		res = "CKM_CAMELLIA_MAC_GENERAL"
	case pkcs11.CKM_CAMELLIA_CBC_PAD:
		res = "CKM_CAMELLIA_CBC_PAD"
	case pkcs11.CKM_CAMELLIA_ECB_ENCRYPT_DATA:
		res = "CKM_CAMELLIA_ECB_ENCRYPT_DATA"
	case pkcs11.CKM_CAMELLIA_CBC_ENCRYPT_DATA:
		res = "CKM_CAMELLIA_CBC_ENCRYPT_DATA"
	case pkcs11.CKM_CAMELLIA_CTR:
		res = "CKM_CAMELLIA_CTR"
	case pkcs11.CKM_ARIA_KEY_GEN:
		res = "CKM_ARIA_KEY_GEN"
	case pkcs11.CKM_ARIA_ECB:
		res = "CKM_ARIA_ECB"
	case pkcs11.CKM_ARIA_CBC:
		res = "CKM_ARIA_CBC"
	case pkcs11.CKM_ARIA_MAC:
		res = "CKM_ARIA_MAC"
	case pkcs11.CKM_ARIA_MAC_GENERAL:
		res = "CKM_ARIA_MAC_GENERAL"
	case pkcs11.CKM_ARIA_CBC_PAD:
		res = "CKM_ARIA_CBC_PAD"
	case pkcs11.CKM_ARIA_ECB_ENCRYPT_DATA:
		res = "CKM_ARIA_ECB_ENCRYPT_DATA"
	case pkcs11.CKM_ARIA_CBC_ENCRYPT_DATA:
		res = "CKM_ARIA_CBC_ENCRYPT_DATA"
	case pkcs11.CKM_SEED_KEY_GEN:
		res = "CKM_SEED_KEY_GEN"
	case pkcs11.CKM_SEED_ECB:
		res = "CKM_SEED_ECB"
	case pkcs11.CKM_SEED_CBC:
		res = "CKM_SEED_CBC"
	case pkcs11.CKM_SEED_MAC:
		res = "CKM_SEED_MAC"
	case pkcs11.CKM_SEED_MAC_GENERAL:
		res = "CKM_SEED_MAC_GENERAL"
	case pkcs11.CKM_SEED_CBC_PAD:
		res = "CKM_SEED_CBC_PAD"
	case pkcs11.CKM_SEED_ECB_ENCRYPT_DATA:
		res = "CKM_SEED_ECB_ENCRYPT_DATA"
	case pkcs11.CKM_SEED_CBC_ENCRYPT_DATA:
		res = "CKM_SEED_CBC_ENCRYPT_DATA"
	case pkcs11.CKM_SKIPJACK_KEY_GEN:
		res = "CKM_SKIPJACK_KEY_GEN"
	case pkcs11.CKM_SKIPJACK_ECB64:
		res = "CKM_SKIPJACK_ECB64"
	case pkcs11.CKM_SKIPJACK_CBC64:
		res = "CKM_SKIPJACK_CBC64"
	case pkcs11.CKM_SKIPJACK_OFB64:
		res = "CKM_SKIPJACK_OFB64"
	case pkcs11.CKM_SKIPJACK_CFB64:
		res = "CKM_SKIPJACK_CFB64"
	case pkcs11.CKM_SKIPJACK_CFB32:
		res = "CKM_SKIPJACK_CFB32"
	case pkcs11.CKM_SKIPJACK_CFB16:
		res = "CKM_SKIPJACK_CFB16"
	case pkcs11.CKM_SKIPJACK_CFB8:
		res = "CKM_SKIPJACK_CFB8"
	case pkcs11.CKM_SKIPJACK_WRAP:
		res = "CKM_SKIPJACK_WRAP"
	case pkcs11.CKM_SKIPJACK_PRIVATE_WRAP:
		res = "CKM_SKIPJACK_PRIVATE_WRAP"
	case pkcs11.CKM_SKIPJACK_RELAYX:
		res = "CKM_SKIPJACK_RELAYX"
	case pkcs11.CKM_KEA_KEY_PAIR_GEN:
		res = "CKM_KEA_KEY_PAIR_GEN"
	case pkcs11.CKM_KEA_KEY_DERIVE:
		res = "CKM_KEA_KEY_DERIVE"
	case pkcs11.CKM_KEA_DERIVE:
		res = "CKM_KEA_DERIVE"
	case pkcs11.CKM_FORTEZZA_TIMESTAMP:
		res = "CKM_FORTEZZA_TIMESTAMP"
	case pkcs11.CKM_BATON_KEY_GEN:
		res = "CKM_BATON_KEY_GEN"
	case pkcs11.CKM_BATON_ECB128:
		res = "CKM_BATON_ECB128"
	case pkcs11.CKM_BATON_ECB96:
		res = "CKM_BATON_ECB96"
	case pkcs11.CKM_BATON_CBC128:
		res = "CKM_BATON_CBC128"
	case pkcs11.CKM_BATON_COUNTER:
		res = "CKM_BATON_COUNTER"
	case pkcs11.CKM_BATON_SHUFFLE:
		res = "CKM_BATON_SHUFFLE"
	case pkcs11.CKM_BATON_WRAP:
		res = "CKM_BATON_WRAP"
	case pkcs11.CKM_EC_KEY_PAIR_GEN:
		res = "CKM_EC_KEY_PAIR_GEN"
	case pkcs11.CKM_ECDSA:
		res = "CKM_ECDSA"
	case pkcs11.CKM_ECDSA_SHA1:
		res = "CKM_ECDSA_SHA1"
	case pkcs11.CKM_ECDSA_SHA224:
		res = "CKM_ECDSA_SHA224"
	case pkcs11.CKM_ECDSA_SHA256:
		res = "CKM_ECDSA_SHA256"
	case pkcs11.CKM_ECDSA_SHA384:
		res = "CKM_ECDSA_SHA384"
	case pkcs11.CKM_ECDSA_SHA512:
		res = "CKM_ECDSA_SHA512"
	case pkcs11.CKM_ECDH1_DERIVE:
		res = "CKM_ECDH1_DERIVE"
	case pkcs11.CKM_ECDH1_COFACTOR_DERIVE:
		res = "CKM_ECDH1_COFACTOR_DERIVE"
	case pkcs11.CKM_ECMQV_DERIVE:
		res = "CKM_ECMQV_DERIVE"
	case pkcs11.CKM_ECDH_AES_KEY_WRAP:
		res = "CKM_ECDH_AES_KEY_WRAP"
	case pkcs11.CKM_RSA_AES_KEY_WRAP:
		res = "CKM_RSA_AES_KEY_WRAP"
	case pkcs11.CKM_JUNIPER_KEY_GEN:
		res = "CKM_JUNIPER_KEY_GEN"
	case pkcs11.CKM_JUNIPER_ECB128:
		res = "CKM_JUNIPER_ECB128"
	case pkcs11.CKM_JUNIPER_CBC128:
		res = "CKM_JUNIPER_CBC128"
	case pkcs11.CKM_JUNIPER_COUNTER:
		res = "CKM_JUNIPER_COUNTER"
	case pkcs11.CKM_JUNIPER_SHUFFLE:
		res = "CKM_JUNIPER_SHUFFLE"
	case pkcs11.CKM_JUNIPER_WRAP:
		res = "CKM_JUNIPER_WRAP"
	case pkcs11.CKM_FASTHASH:
		res = "CKM_FASTHASH"
	case pkcs11.CKM_AES_KEY_GEN:
		res = "CKM_AES_KEY_GEN"
	case pkcs11.CKM_AES_ECB:
		res = "CKM_AES_ECB"
	case pkcs11.CKM_AES_CBC:
		res = "CKM_AES_CBC"
	case pkcs11.CKM_AES_MAC:
		res = "CKM_AES_MAC"
	case pkcs11.CKM_AES_MAC_GENERAL:
		res = "CKM_AES_MAC_GENERAL"
	case pkcs11.CKM_AES_CBC_PAD:
		res = "CKM_AES_CBC_PAD"
	case pkcs11.CKM_AES_CTR:
		res = "CKM_AES_CTR"
	case pkcs11.CKM_AES_GCM:
		res = "CKM_AES_GCM"
	case pkcs11.CKM_AES_CCM:
		res = "CKM_AES_CCM"
	case pkcs11.CKM_AES_CTS:
		res = "CKM_AES_CTS"
	case pkcs11.CKM_AES_CMAC:
		res = "CKM_AES_CMAC"
	case pkcs11.CKM_AES_CMAC_GENERAL:
		res = "CKM_AES_CMAC_GENERAL"
	case pkcs11.CKM_AES_XCBC_MAC:
		res = "CKM_AES_XCBC_MAC"
	case pkcs11.CKM_AES_XCBC_MAC_96:
		res = "CKM_AES_XCBC_MAC_96"
	case pkcs11.CKM_AES_GMAC:
		res = "CKM_AES_GMAC"
	case pkcs11.CKM_BLOWFISH_KEY_GEN:
		res = "CKM_BLOWFISH_KEY_GEN"
	case pkcs11.CKM_BLOWFISH_CBC:
		res = "CKM_BLOWFISH_CBC"
	case pkcs11.CKM_TWOFISH_KEY_GEN:
		res = "CKM_TWOFISH_KEY_GEN"
	case pkcs11.CKM_TWOFISH_CBC:
		res = "CKM_TWOFISH_CBC"
	case pkcs11.CKM_BLOWFISH_CBC_PAD:
		res = "CKM_BLOWFISH_CBC_PAD"
	case pkcs11.CKM_TWOFISH_CBC_PAD:
		res = "CKM_TWOFISH_CBC_PAD"
	case pkcs11.CKM_DES_ECB_ENCRYPT_DATA:
		res = "CKM_DES_ECB_ENCRYPT_DATA"
	case pkcs11.CKM_DES_CBC_ENCRYPT_DATA:
		res = "CKM_DES_CBC_ENCRYPT_DATA"
	case pkcs11.CKM_DES3_ECB_ENCRYPT_DATA:
		res = "CKM_DES3_ECB_ENCRYPT_DATA"
	case pkcs11.CKM_DES3_CBC_ENCRYPT_DATA:
		res = "CKM_DES3_CBC_ENCRYPT_DATA"
	case pkcs11.CKM_AES_ECB_ENCRYPT_DATA:
		res = "CKM_AES_ECB_ENCRYPT_DATA"
	case pkcs11.CKM_AES_CBC_ENCRYPT_DATA:
		res = "CKM_AES_CBC_ENCRYPT_DATA"
	case pkcs11.CKM_GOSTR3410_KEY_PAIR_GEN:
		res = "CKM_GOSTR3410_KEY_PAIR_GEN"
	case pkcs11.CKM_GOSTR3410:
		res = "CKM_GOSTR3410"
	case pkcs11.CKM_GOSTR3410_WITH_GOSTR3411:
		res = "CKM_GOSTR3410_WITH_GOSTR3411"
	case pkcs11.CKM_GOSTR3410_KEY_WRAP:
		res = "CKM_GOSTR3410_KEY_WRAP"
	case pkcs11.CKM_GOSTR3410_DERIVE:
		res = "CKM_GOSTR3410_DERIVE"
	case pkcs11.CKM_GOSTR3411:
		res = "CKM_GOSTR3411"
	case pkcs11.CKM_GOSTR3411_HMAC:
		res = "CKM_GOSTR3411_HMAC"
	case pkcs11.CKM_GOST28147_KEY_GEN:
		res = "CKM_GOST28147_KEY_GEN"
	case pkcs11.CKM_GOST28147_ECB:
		res = "CKM_GOST28147_ECB"
	case pkcs11.CKM_GOST28147:
		res = "CKM_GOST28147"
	case pkcs11.CKM_GOST28147_MAC:
		res = "CKM_GOST28147_MAC"
	case pkcs11.CKM_GOST28147_KEY_WRAP:
		res = "CKM_GOST28147_KEY_WRAP"
	case pkcs11.CKM_DSA_PARAMETER_GEN:
		res = "CKM_DSA_PARAMETER_GEN"
	case pkcs11.CKM_DH_PKCS_PARAMETER_GEN:
		res = "CKM_DH_PKCS_PARAMETER_GEN"
	case pkcs11.CKM_X9_42_DH_PARAMETER_GEN:
		res = "CKM_X9_42_DH_PARAMETER_GEN"
	case pkcs11.CKM_DSA_PROBABLISTIC_PARAMETER_GEN:
		res = "CKM_DSA_PROBABLISTIC_PARAMETER_GEN"
	case pkcs11.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN:
		res = "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN"
	case pkcs11.CKM_AES_OFB:
		res = "CKM_AES_OFB"
	case pkcs11.CKM_AES_CFB64:
		res = "CKM_AES_CFB64"
	case pkcs11.CKM_AES_CFB8:
		res = "CKM_AES_CFB8"
	case pkcs11.CKM_AES_CFB128:
		res = "CKM_AES_CFB128"
	case pkcs11.CKM_AES_CFB1:
		res = "CKM_AES_CFB1"
	case pkcs11.CKM_AES_KEY_WRAP:
		res = "CKM_AES_KEY_WRAP"
	case pkcs11.CKM_AES_KEY_WRAP_PAD:
		res = "CKM_AES_KEY_WRAP_PAD"
	case pkcs11.CKM_RSA_PKCS_TPM_1_1:
		res = "CKM_RSA_PKCS_TPM_1_1"
	case pkcs11.CKM_RSA_PKCS_OAEP_TPM_1_1:
		res = "CKM_RSA_PKCS_OAEP_TPM_1_1"
	case pkcs11.CKM_VENDOR_DEFINED:
		res = "CKM_VENDOR_DEFINED"
	default:
		err = errors.New("Unrecognised")
	}
	return
}
