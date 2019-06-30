module main

#flag darwin -lcrypto
#flag linux -lcrypto

#include <openssl/rsa.h>
#include <openssl/pem.h>

import const (
	BIO_pending
)

struct C.RSA
struct C.BN_GENCB
struct C.BIGNUM
struct C.BIO
struct C.BIO_METHOD

fn C.RSA_generate_key_ex(*C.RSA, int, *C.BIGNUM, *C.BN_GENCB) int
fn C.BN_set_word(*C.BIGNUM, int) int
fn C.BN_new() *C.BIGNUM
fn C.RSA_new() *C.RSA
fn C.RSA_bits(*C.RSA) int
fn C.RSA_size(*C.RSA) int
fn C.BIO_read(*C.BIO, voidptr, int) int
fn C.BIO_new(*C.BIO_METHOD) *C.BIO
fn C.BIO_new_mem_buf(voidptr, int) *C.BIO
fn C.BIO_new_file(byteptr, byteptr) *C.BIO
fn C.PEM_write_bio_RSAPublicKey(*C.BIO, *C.RSA) int
fn C.PEM_write_bio_RSAPrivateKey(*C.BIO, *C.RSA, voidptr, voidptr, int, voidptr, voidptr) int
fn C.BIO_free_all(*C.BIO)
fn C.BIO_free_all(*C.BIO)
fn C.RSA_free(*C.RSA)
fn C.BN_free(*C.BIGNUM)
fn C.BIO_s_mem() *C.BIO_METHOD

pub fn generate_rsa_key(bits, exp int) {
	bne := BN_new()

	mut ret := BN_set_word(bne, exp)
	if ret != 1 {
		panic('FAILED!')
	}

	r := RSA_new()
	ret = RSA_generate_key_ex(r, bits, bne, 0)
	if (ret != 1) {
		panic('FAILED!')
	}

	pub_bio := C.BIO_new(C.BIO_s_mem())
	pri_bio := C.BIO_new(C.BIO_s_mem())

	ret = C.PEM_write_bio_RSAPrivateKey(pri_bio, r, 0, 0, 0, 0, 0)
	if (ret != 1) {
		panic('FAILED!')
	}

	ret = C.PEM_write_bio_RSAPublicKey(pub_bio, r)
	if (ret != 1) {
		panic('FAILED!')
	}

	pri_len := int(C.BIO_pending(pri_bio))
	pub_len := int(C.BIO_pending(pub_bio))

	mut pri_key := malloc(pri_len + 1)
	mut pub_key := malloc(pub_len + 1)

	BIO_read(pri_bio, pri_key, pri_len)
	BIO_read(pub_bio, pub_key, pub_len)

	pri_key[pri_len] = 0
	pub_key[pub_len] = 0

	println(tos(pri_key, pri_len))
	println(tos(pub_key, pub_len))

	C.BIO_free_all(pub_bio)
	C.BIO_free_all(pri_key)
	C.RSA_free(r)
	C.BN_free(bne)
}
