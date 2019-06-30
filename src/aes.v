module main

#flag darwin -lcrypto
#flag linux -lcrypto

#include <openssl/aes.h>

struct C.AES_KEY

import const (
	AES_BLOCK_SIZE
)

fn C.AES_set_encrypt_key(byteptr, int, *AES_KEY) int
fn C.AES_set_decrypt_key(byteptr, int, *AES_KEY) int
fn C.AES_encrypt(byteptr, byteptr, *AES_KEY)
fn C.AES_decrypt(byteptr, byteptr, *AES_KEY)

pub fn aes_encrypt(key, str string) string {
	enc_key := &C.AES_KEY{}
	enc_out := calloc(str.len + (AES_BLOCK_SIZE - (str.len % AES_BLOCK_SIZE)) + 1)

	C.AES_set_encrypt_key(key.str, 128, enc_key)
	C.AES_encrypt(str.str, enc_out, enc_key)

	return tos(enc_out, strlen(enc_out))
}

pub fn aes_decrypt(key, str string) string {
	dec_key := &C.AES_KEY{}
	dec_out := malloc(str.len)

	C.AES_set_decrypt_key(key.str, 128, dec_key)
  C.AES_decrypt(str.str, dec_out, dec_key)

	return tos(dec_out, strlen(dec_out))
}
