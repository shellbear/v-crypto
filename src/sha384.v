module main

#flag darwin -lcrypto
#flag linux -lcrypto

#include <stdio.h>
#include <openssl/sha.h>

import const (
	SHA384_DIGEST_LENGTH
)

fn C.SHA384_Init(*C.SHA512_CTX) int
fn C.SHA384_Update(*C.SHA512_CTX, voidptr, u64) int
fn C.SHA384_Final(byteptr, *C.SHA512_CTX) int
fn C.SHA384(byteptr, u64, byteptr) byteptr
fn C.SHA384_Transform(*C.SHA512_CTX, byteptr)

pub fn sha384(str string, uppercase bool) string {
	context := &C.SHA512_CTX{}
	mut digest := malloc(SHA384_DIGEST_LENGTH)
	mut out := malloc(SHA384_DIGEST_LENGTH * 2 + 1)
	format := if uppercase { '%02X' } else { '%02x' }

	C.SHA384_Init(context)
	C.SHA384_Update(context, str.str, str.len)
	C.SHA384_Final(digest, context)

	for i := 0; i < SHA384_DIGEST_LENGTH; i++ {
		C.sprintf(&out[i * 2], format.str, digest[i])
	}

	return tos(out, SHA384_DIGEST_LENGTH * 2)
}
