module main

fn main() {
	key := 'uFU8bJFFAaqzrve3sQ28p5SUgu4zbPUt'
	str := 'Hello world!'

	encrypted := aes_encrypt(key, str)
	decrypted := aes_decrypt(key, encrypted)

	println('Original: $str')
	println('Encrypted: $encrypted')
	println('Decrypted: $decrypted')

	hash_md5 := md5(str, true)
	hash_md4 := md4(str, true)
	sha1_hash := sha1(str, true)
	sha256_hash := sha256(str, true)
	sha384_hash := sha384(str, true)
	sha512_hash := sha512(str, true)

	generate_rsa_key(2048, 0x10001)

	println('MD5: $hash_md5')
	println('MD4: $hash_md4')
	println('SHA1: $sha1_hash')
	println('SHA256: $sha256_hash')
	println('SHA384: $sha384_hash')
	println('SHA512: $sha512_hash')
}
