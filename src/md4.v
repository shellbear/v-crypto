module main

#flag darwin -lcrypto
#flag linux -lcrypto

#include <stdio.h>
#include <openssl/md4.h>

import const (
	MD4_DIGEST_LENGTH
)

struct C.MD4_CTX

fn C.MD4_Init(*C.MD4_CTX) int
fn C.MD4_Update(*C.MD4_CTX, voidptr, u64) int
fn C.MD4_Final(byteptr, *C.MD4_CTX) int
fn C.MD4(byteptr, u64, byteptr) byteptr
fn C.MD4_Transform(*C.MD4_CTX, byteptr)

pub fn md4(str string, uppercase bool) string {
	context := &C.MD4_CTX{}
	mut digest := malloc(MD4_DIGEST_LENGTH)
	mut out := malloc(MD4_DIGEST_LENGTH * 2 + 1)
	format := if uppercase { '%02X' } else { '%02x' }

	C.MD4_Init(context)
	C.MD4_Update(context, str.str, str.len)
	C.MD4_Final(digest, context)

	for i := 0; i < MD4_DIGEST_LENGTH; i++ {
		C.sprintf(&out[i * 2], format.str, digest[i])
	}

	return tos(out, MD4_DIGEST_LENGTH * 2)
}
