module main

#flag darwin -lcrypto
#flag linux -lcrypto

#include <stdio.h>
#include <openssl/sha.h>

import const (
	SHA512_DIGEST_LENGTH
)

struct C.SHA512_CTX

fn C.SHA512_Init(*C.SHA512_CTX) int
fn C.SHA512_Update(*C.SHA512_CTX, voidptr, u64) int
fn C.SHA512_Final(byteptr, *C.SHA512_CTX) int
fn C.SHA512(byteptr, u64, byteptr) byteptr
fn C.SHA512_Transform(*C.SHA512_CTX, byteptr)

pub fn sha512(str string, uppercase bool) string {
	context := &C.SHA512_CTX{}
	mut digest := malloc(SHA512_DIGEST_LENGTH)
	mut out := malloc(SHA512_DIGEST_LENGTH * 2 + 1)
	format := if uppercase { '%02X' } else { '%02x' }

	C.SHA512_Init(context)
	C.SHA512_Update(context, str.str, str.len)
	C.SHA512_Final(digest, context)

	for i := 0; i < SHA512_DIGEST_LENGTH; i++ {
		C.sprintf(&out[i * 2], format.str, digest[i])
	}

	return tos(out, SHA512_DIGEST_LENGTH * 2)
}
