/*
This is a simple implementation of ECDSA.
   */
#include "secp256k1.h"
#include <string.h>
#include <stdio.h>

int main(int argc, char** argv){
	secp256k1_context* ctx;
	unsigned char sk[32];
	// msg: aaa
	unsigned char msg[] = "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0";
	printf("msg length: %d\n", strlen(msg));

	// initialize
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
	int i;

	// secret key
	printf("secret key:");
	for(i = 0; i < 32; ++i){
		sk[i] = i + 65;
		printf("%0X", sk[i]);
	}
	printf("\n");

	// msg hash
   	for(i = 0; i < 32; ++i){
//		msg[i] = i + 1;
	}

	unsigned char sig[74];
	size_t siglen = 74;
	secp256k1_ecdsa_signature signature;
	secp256k1_ecdsa_sign(ctx, &signature, msg, sk, NULL, NULL);
	secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature);

	// print signature
	printf("ECDSA signature:");
	for(i = 0; i < 74; ++i){
		printf("%0X", sig[i]);
	}
	printf("\n");
	
	// verify
	secp256k1_pubkey pk;
	secp256k1_ec_pubkey_create(ctx, &pk, sk);
	int flag = secp256k1_ecdsa_verify(ctx, sig, msg, &pk);
	if(flag == 0) puts("signature verify pass!!");
	else puts("signature verify failed!");
	
	// free
	secp256k1_context_destroy(ctx);
	return 0;
}
