#include "tests.h"
#include "unity.h"
#include "aes.h"
#include "stdint.h"
#include "stdio.h"

static const  uint8_t key[AES_KEYLEN]  = { 0x50, 0x65, 0x53, 0x68, 0x56, 0x6D, 0x59, 0x71, 0x33, 0x74, 0x36, 0x77, 0x39, 0x79, 0x24, 0x42 };
static const  uint8_t iv[AES_BLOCKLEN] = { 0x25, 0x43, 0x2A, 0x46, 0x2D, 0x4A, 0x61, 0x4E, 0x63, 0x52, 0x66, 0x55, 0x6A, 0x58, 0x6E, 0x32 };
static struct AES_ctx ctx              = { 0U };

#define TEST_DATA_LENGTH 32U
static const uint8_t inputData[TEST_DATA_LENGTH]     = { 
  0xd0, 0xff, 0x2d, 0x67, 0xd0, 0x42, 0x92, 0x6d, 0x1d, 0xb7, 0xe4, 0x28, 0xc3, 0x5f, 0x9b, 0xea,
  0x87, 0x13, 0x86, 0x62, 0x50, 0xca, 0xb3, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t encriptEtalon[TEST_DATA_LENGTH] = { 
  0x74, 0x2f, 0x3d, 0x8e, 0xa9, 0xd4, 0x35, 0x23, 0xcd, 0xca, 0x97, 0x6a, 0x6a, 0xb6, 0xc5, 0xe8,
  0x34, 0x27, 0x8c, 0x04, 0x49, 0x79, 0xd4, 0x50, 0x4b, 0x85, 0x63, 0x63, 0x63, 0x59, 0x97, 0x31 };
static uint8_t  buffer[TEST_DATA_LENGTH]             = { 0U };
static uint32_t length                               = TEST_DATA_LENGTH;

// http://aes.online-domain-tools.com/
// key:    50 65 53 68 56 6D 59 71 33 74 36 77 39 79 24 42
// vector: 25 43 2A 46 2D 4A 61 4E 63 52 66 55 6A 58 6E 32
// input:  d0 ff 2d 67 d0 42 92 6d 1d b7 e4 28 c3 5f 9b ea 87 13 86 62 50 ca b3 6f 00 00 00 00 00 00 00 00
// output: 74	2f	3d	8e	a9	d4	35	23	cd	ca	97	6a	6a	b6	c5	e8 34	27	8c	04	49	79	d4	50	4b	85	63	63	63	59	97	31


void test_AES_CBC_encrypt_decrypt_buffer ( void )
{
  for ( uint32_t i=0U; i<TEST_DATA_LENGTH; i++ )
  {
    buffer[i] = inputData[i];
  }
  AES_init_ctx_iv( &ctx, key, iv );
  AES_CBC_encrypt_buffer( &ctx, buffer, length );
  for ( uint32_t i=0U; i<TEST_DATA_LENGTH; i++ )
  {
    TEST_ASSERT_EQUAL_UINT8( encriptEtalon[i], buffer[i] );
  }

  AES_init_ctx_iv( &ctx, key, iv );
  AES_CBC_decrypt_buffer( &ctx, buffer, length );
  for ( uint32_t i=0U; i<TEST_DATA_LENGTH; i++ )
  {
    TEST_ASSERT_EQUAL( inputData[i], buffer[i] );
  }
  return;
}

void test_aes ( void )
{
  UnitySetTestFile( "test_aes.c" );
  UnityDefaultTestRun( test_AES_CBC_encrypt_decrypt_buffer, "Test AES encyption and decryption", 28U );
  return;
}