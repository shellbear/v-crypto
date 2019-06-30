module main

#flag darwin -lcrypto
#flag linux -lcrypto

#include <stdio.h>
#include <openssl/sha.h>

import const (
	SHA256_DIGEST_LENGTH
)

struct C.SHA256_CTX

fn C.SHA256_Init(*C.SHA256_CTX) int
fn C.SHA256_Update(*C.SHA256_CTX, voidptr, u64) int
fn C.SHA256_Final(byteptr, *C.SHA256_CTX) int
fn C.SHA256(byteptr, u64, byteptr) byteptr
fn C.SHA256_Transform(*C.SHA256_CTX, byteptr)

pub fn sha256(str string, uppercase bool) string {
	context := &C.SHA256_CTX{}
	mut digest := malloc(SHA256_DIGEST_LENGTH)
	mut out := malloc(SHA256_DIGEST_LENGTH * 2 + 1)
	format := if uppercase { '%02X' } else { '%02x' }

	C.SHA256_Init(context)
	C.SHA256_Update(context, str.str, str.len)
	C.SHA256_Final(digest, context)

	for i := 0; i < SHA256_DIGEST_LENGTH; i++ {
		C.sprintf(&out[i * 2], format.str, digest[i])
	}

	return tos(out, SHA256_DIGEST_LENGTH * 2)
}
