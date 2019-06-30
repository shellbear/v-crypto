module main

#flag darwin -lcrypto
#flag linux -lcrypto

#include <stdio.h>
#include <openssl/md5.h>

import const (
	MD5_DIGEST_LENGTH
)

struct C.MD5_CTX

fn C.MD5_Init(*C.MD5_CTX) int
fn C.MD5_Update(*C.MD5_CTX, voidptr, u64) int
fn C.MD5_Final(byteptr, *C.MD5_CTX) int
fn C.MD5(byteptr, u64, byteptr) byteptr
fn C.MD5_Transform(*C.MD5_CTX, byteptr)

pub fn md5(str string, uppercase bool) string {
	context := &C.MD5_CTX{}
	mut digest := malloc(MD5_DIGEST_LENGTH)
	mut out := malloc(MD5_DIGEST_LENGTH * 2 + 1)
	format := if uppercase { '%02X' } else { '%02x' }

	C.MD5_Init(context)
	C.MD5_Update(context, str.str, str.len)
	C.MD5_Final(digest, context)

	for i := 0; i < MD5_DIGEST_LENGTH; i++ {
		C.sprintf(&out[i * 2], format.str, digest[i])
	}

	return tos(out, MD5_DIGEST_LENGTH * 2)
}
