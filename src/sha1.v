module main

#flag darwin -lcrypto
#flag linux -lcrypto

#include <stdio.h>
#include <openssl/sha.h>

import const (
	SHA_DIGEST_LENGTH
)

struct C.SHA_CTX

fn C.SHA1_Init(*C.SHA_CTX) int
fn C.SHA1_Update(*C.SHA_CTX, voidptr, u64) int
fn C.SHA1_Final(byteptr, *C.SHA_CTX) int
fn C.SHA1(byteptr, u64, byteptr) byteptr
fn C.SHA1_Transform(*C.SHA_CTX, byteptr)

pub fn sha1(str string, uppercase bool) string {
	context := &C.SHA_CTX{}
	mut digest := malloc(SHA_DIGEST_LENGTH)
	mut out := malloc(SHA_DIGEST_LENGTH * 2 + 1)
	format := if uppercase { '%02X' } else { '%02x' }

	C.SHA1_Init(context)
	C.SHA1_Update(context, str.str, str.len)
	C.SHA1_Final(digest, context)

	for i := 0; i < SHA_DIGEST_LENGTH; i++ {
		C.sprintf(&out[i * 2], format.str, digest[i])
	}

	return tos(out, SHA_DIGEST_LENGTH * 2)
}
