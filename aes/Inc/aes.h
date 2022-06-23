#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#define CBC            1U    /* Cipher Block Chaining  */
#define ECB            0U    /* Electronic Codebook */
#define CTR 	         0U    /* Counter mode */
#define AES128         1U
#define AES_BLOCKLEN   16U   /* Block length in bytes - AES is 128b block only */
#define AES_KEYLEN     16U   /* Key length in bytes */
#define AES_keyExpSize 176U

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
  #if ( defined( CBC ) && ( CBC == 1U ) ) || ( defined( CTR ) && ( CTR == 1U ) )
    uint8_t Iv[AES_BLOCKLEN];
  #endif
};

void AES_init_ctx ( struct AES_ctx* ctx, const uint8_t* key );
#if ( defined( CBC ) && ( CBC == 1U ) ) || ( defined( CTR ) && ( CTR == 1U ) )
  void AES_init_ctx_iv ( struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv );
  void AES_ctx_set_iv ( struct AES_ctx* ctx, const uint8_t* iv );
#endif

#if defined( ECB ) && ( ECB == 1U )
  // buffer size is exactly AES_BLOCKLEN bytes;
  // you need only AES_init_ctx as IV is not used in ECB
  // NB: ECB is considered insecure for most uses
  void AES_ECB_encrypt ( const struct AES_ctx* ctx, uint8_t* buf );
  void AES_ECB_decrypt ( const struct AES_ctx* ctx, uint8_t* buf );
#endif // #if defined(ECB) && (ECB == !)


#if defined( CBC ) && ( CBC == 1U )
  // buffer size MUST be mutile of AES_BLOCKLEN;
  // Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
  // NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
  //        no IV should ever be reused with the same key
  void AES_CBC_encrypt_buffer ( struct AES_ctx* ctx, uint8_t* buf, uint32_t length );
  void AES_CBC_decrypt_buffer ( struct AES_ctx* ctx, uint8_t* buf, uint32_t length );
#endif // #if defined(CBC) && (CBC == 1)


#if defined( CTR ) && ( CTR == 1U )
  // Same function for encrypting as for decrypting.
  // IV is incremented for every block, and used after encryption as XOR-compliment for output
  // Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
  // NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
  //        no IV should ever be reused with the same key
  void AES_CTR_xcrypt_buffer ( struct AES_ctx* ctx, uint8_t* buf, uint32_t length );
#endif // #if defined(CTR) && (CTR == 1)


#endif // _AES_H_
