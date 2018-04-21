/*
This is a simple implementation of ECDSA.
   */
#include "include/secp256k1.h"
#include "hash.h"
#include <string.h>
#include <stdio.h>

int main(int argc, char** argv){
	secp256k1_context* ctx;
	unsigned char sk[32];

	// initialize
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	int i;

	// secret key
	for(int i = 0; i < 32; ++i){
		sk[i] = i + 65;
	}
	printf("secret key:%s\n", sk);

	// calculate hash of the message
	unsigned char msg[] = "This is just a test message";
	unsigned char hash_msg[32];
	secp256k1_sha256 hash;
	secp256k1_sha256_initialize(&hash);
	secp256k1_sha256_write(&hash, msg, strlen(msg));
	secp256k1_sha256_finalize(&hash, hash_msg);
	printf("SHA256 hash of the msg: %s\n", hash_msg);

	//unsigned char sig[75];
	

	// free
	secp256k1_context_destory(ctx);
}
