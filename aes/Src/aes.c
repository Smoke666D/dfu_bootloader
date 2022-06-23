/*

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97 
    f5d3d58503b9699de785895a96fdbaaf 
    43b1cd7f598ece23881b00e3ed030688 
    7b0c785e27e8ad3f8223207104725dd4 


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h> // CBC mode, for memset
#include "aes.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4U
#define Nk 4U        // The number of 32 bit words in a key.
#define Nr 10U       // The number of rounds in AES Cipher.

#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \
/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4U][4U];
// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256U] = {
//  0      1      2      3      4      5      6      7      8      9      A      B      C      D      E      F
  0x63U, 0x7CU, 0x77U, 0x7BU, 0xF2U, 0x6BU, 0x6FU, 0xC5U, 0x30U, 0x01U, 0x67U, 0x2BU, 0xFEU, 0xD7U, 0xABU, 0x76U,
  0xCAU, 0x82U, 0xC9U, 0x7DU, 0xFAU, 0x59U, 0x47U, 0xF0U, 0xADU, 0xD4U, 0xA2U, 0xAFU, 0x9CU, 0xA4U, 0x72U, 0xC0U,
  0xB7U, 0xFDU, 0x93U, 0x26U, 0x36U, 0x3FU, 0xF7U, 0xCCU, 0x34U, 0xA5U, 0xE5U, 0xF1U, 0x71U, 0xD8U, 0x31U, 0x15U,
  0x04U, 0xC7U, 0x23U, 0xC3U, 0x18U, 0x96U, 0x05U, 0x9AU, 0x07U, 0x12U, 0x80U, 0xE2U, 0xEBU, 0x27U, 0xB2U, 0x75U,
  0x09U, 0x83U, 0x2CU, 0x1AU, 0x1BU, 0x6EU, 0x5AU, 0xA0U, 0x52U, 0x3BU, 0xD6U, 0xB3U, 0x29U, 0xE3U, 0x2FU, 0x84U,
  0x53U, 0xD1U, 0x00U, 0xEDU, 0x20U, 0xFCU, 0xB1U, 0x5BU, 0x6AU, 0xCBU, 0xBEU, 0x39U, 0x4AU, 0x4CU, 0x58U, 0xCFU,
  0xD0U, 0xEFU, 0xAAU, 0xFBU, 0x43U, 0x4DU, 0x33U, 0x85U, 0x45U, 0xF9U, 0x02U, 0x7FU, 0x50U, 0x3CU, 0x9FU, 0xA8U,
  0x51U, 0xA3U, 0x40U, 0x8FU, 0x92U, 0x9DU, 0x38U, 0xF5U, 0xBCU, 0xB6U, 0xDAU, 0x21U, 0x10U, 0xFFU, 0xF3U, 0xD2U,
  0xCDU, 0x0CU, 0x13U, 0xECU, 0x5FU, 0x97U, 0x44U, 0x17U, 0xC4U, 0xA7U, 0x7EU, 0x3DU, 0x64U, 0x5DU, 0x19U, 0x73U,
  0x60U, 0x81U, 0x4FU, 0xDCU, 0x22U, 0x2AU, 0x90U, 0x88U, 0x46U, 0xEEU, 0xB8U, 0x14U, 0xDEU, 0x5EU, 0x0BU, 0xDBU,
  0xE0U, 0x32U, 0x3AU, 0x0AU, 0x49U, 0x06U, 0x24U, 0x5CU, 0xC2U, 0xD3U, 0xACU, 0x62U, 0x91U, 0x95U, 0xE4U, 0x79U,
  0xE7U, 0xC8U, 0x37U, 0x6DU, 0x8DU, 0xD5U, 0x4EU, 0xA9U, 0x6CU, 0x56U, 0xF4U, 0xEAU, 0x65U, 0x7AU, 0xAEU, 0x08U,
  0xBAU, 0x78U, 0x25U, 0x2EU, 0x1CU, 0xA6U, 0xB4U, 0xC6U, 0xE8U, 0xDDU, 0x74U, 0x1FU, 0x4BU, 0xBDU, 0x8BU, 0x8AU,
  0x70U, 0x3EU, 0xB5U, 0x66U, 0x48U, 0x03U, 0xF6U, 0x0EU, 0x61U, 0x35U, 0x57U, 0xB9U, 0x86U, 0xC1U, 0x1DU, 0x9EU,
  0xE1U, 0xF8U, 0x98U, 0x11U, 0x69U, 0xD9U, 0x8EU, 0x94U, 0x9BU, 0x1EU, 0x87U, 0xE9U, 0xCEU, 0x55U, 0x28U, 0xDFU,
  0x8CU, 0xA1U, 0x89U, 0x0DU, 0xBFU, 0xE6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2DU, 0x0FU, 0xB0U, 0x54U, 0xBBU, 0x16U };

static const uint8_t rsbox[256U] = {
//  0      1      2      3      4      5      6      7      8      9      A      B      C      D      E      F  
  0x52U, 0x09U, 0x6AU, 0xD5U, 0x30U, 0x36U, 0xA5U, 0x38U, 0xBFU, 0x40U, 0xA3U, 0x9EU, 0x81U, 0xF3U, 0xD7U, 0xFBU,
  0x7CU, 0xE3U, 0x39U, 0x82U, 0x9BU, 0x2FU, 0xFFU, 0x87U, 0x34U, 0x8EU, 0x43U, 0x44U, 0xC4U, 0xDEU, 0xE9U, 0xCBU,
  0x54U, 0x7BU, 0x94U, 0x32U, 0xA6U, 0xC2U, 0x23U, 0x3DU, 0xEEU, 0x4CU, 0x95U, 0x0BU, 0x42U, 0xFAU, 0xC3U, 0x4EU,
  0x08U, 0x2EU, 0xA1U, 0x66U, 0x28U, 0xD9U, 0x24U, 0xB2U, 0x76U, 0x5BU, 0xA2U, 0x49U, 0x6DU, 0x8BU, 0xD1U, 0x25U,
  0x72U, 0xF8U, 0xF6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U, 0xD4U, 0xA4U, 0x5CU, 0xCCU, 0x5DU, 0x65U, 0xB6U, 0x92U,
  0x6CU, 0x70U, 0x48U, 0x50U, 0xFDU, 0xEDU, 0xB9U, 0xDAU, 0x5EU, 0x15U, 0x46U, 0x57U, 0xA7U, 0x8DU, 0x9DU, 0x84U,
  0x90U, 0xD8U, 0xABU, 0x00U, 0x8CU, 0xBCU, 0xD3U, 0x0AU, 0xF7U, 0xE4U, 0x58U, 0x05U, 0xB8U, 0xB3U, 0x45U, 0x06U,
  0xD0U, 0x2CU, 0x1EU, 0x8FU, 0xCAU, 0x3FU, 0x0FU, 0x02U, 0xC1U, 0xAFU, 0xBDU, 0x03U, 0x01U, 0x13U, 0x8AU, 0x6BU,
  0x3AU, 0x91U, 0x11U, 0x41U, 0x4FU, 0x67U, 0xDCU, 0xEAU, 0x97U, 0xF2U, 0xCFU, 0xCEU, 0xF0U, 0xB4U, 0xE6U, 0x73U,
  0x96U, 0xACU, 0x74U, 0x22U, 0xE7U, 0xADU, 0x35U, 0x85U, 0xE2U, 0xF9U, 0x37U, 0xE8U, 0x1CU, 0x75U, 0xDFU, 0x6EU,
  0x47U, 0xF1U, 0x1AU, 0x71U, 0x1DU, 0x29U, 0xC5U, 0x89U, 0x6FU, 0xB7U, 0x62U, 0x0EU, 0xAAU, 0x18U, 0xBEU, 0x1BU,
  0xFCU, 0x56U, 0x3EU, 0x4BU, 0xC6U, 0xD2U, 0x79U, 0x20U, 0x9AU, 0xDBU, 0xC0U, 0xFEU, 0x78U, 0xCDU, 0x5AU, 0xF4U,
  0x1FU, 0xDDU, 0xA8U, 0x33U, 0x88U, 0x07U, 0xC7U, 0x31U, 0xB1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xECU, 0x5FU,
  0x60U, 0x51U, 0x7FU, 0xA9U, 0x19U, 0xB5U, 0x4AU, 0x0DU, 0x2DU, 0xE5U, 0x7AU, 0x9FU, 0x93U, 0xC9U, 0x9CU, 0xEFU,
  0xA0U, 0xE0U, 0x3BU, 0x4DU, 0xAEU, 0x2AU, 0xF5U, 0xB0U, 0xC8U, 0xEBU, 0xBBU, 0x3CU, 0x83U, 0x53U, 0x99U, 0x61U,
  0x17U, 0x2BU, 0x04U, 0x7EU, 0xBAU, 0x77U, 0xD6U, 0x26U, 0xE1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0CU, 0x7DU };
// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11U] = {
  0x8dU, 0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U, 0x1bU, 0x36U };


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
#define getSBoxValue( num )  ( sbox[( num )])
#define getSBoxInvert( num ) ( rsbox[( num )])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion ( uint8_t* RoundKey, const uint8_t* Key )
{
  uint8_t k = 0U;
  uint8_t tempa[4U] = { 0U }; // Used for the column/row operations 
  // The first round key is the key itself.
  for ( uint8_t i=0U; i<Nk; ++i )
  {
    RoundKey[(i * 4U)]      = Key[(i * 4U)];
    RoundKey[(i * 4U) + 1U] = Key[(i * 4U) + 1U];
    RoundKey[(i * 4U) + 2U] = Key[(i * 4U) + 2U];
    RoundKey[(i * 4U) + 3U] = Key[(i * 4U) + 3U];
  }
  // All other round keys are found from the previous round keys.
  for ( uint8_t i=Nk; i<(Nb * ( Nr + 1U ) ); ++i )
  {
    k = ( i - 1U ) * 4U;
    tempa[0U] = RoundKey[k];
    tempa[1U] = RoundKey[k + 1U];
    tempa[2U] = RoundKey[k + 2U];
    tempa[3U] = RoundKey[k + 3U];
    if ( ( i % Nk ) == 0U )
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
      const uint8_t u8tmp = tempa[0U];
      tempa[0U] = tempa[1U];
      tempa[1U] = tempa[2U];
      tempa[2U] = tempa[3U];
      tempa[3U] = u8tmp;
      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.
      tempa[0U] = getSBoxValue(tempa[0U]);
      tempa[1U] = getSBoxValue(tempa[1U]);
      tempa[2U] = getSBoxValue(tempa[2U]);
      tempa[3U] = getSBoxValue(tempa[3U]);
      tempa[0U] = tempa[0U] ^ Rcon[i/Nk];
    }
    uint8_t j = i * 4U;
    uint8_t k = (i - Nk) * 4U;
    RoundKey[j]      = RoundKey[k]      ^ tempa[0U];
    RoundKey[j + 1U] = RoundKey[k + 1U] ^ tempa[1U];
    RoundKey[j + 2U] = RoundKey[k + 2U] ^ tempa[2U];
    RoundKey[j + 3U] = RoundKey[k + 3U] ^ tempa[3U];
  }
  return;
}

void AES_init_ctx ( struct AES_ctx* ctx, const uint8_t* key )
{
  KeyExpansion( ctx->RoundKey, key );
  return;
}

#if ( defined( CBC ) && ( CBC == 1U ) ) || ( defined( CTR ) && ( CTR == 1U ) )
void AES_init_ctx_iv ( struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv )
{
  KeyExpansion( ctx->RoundKey, key );
  memcpy ( ctx->Iv, iv, AES_BLOCKLEN );
  return;
}
void AES_ctx_set_iv( struct AES_ctx* ctx, const uint8_t* iv )
{
  memcpy ( ctx->Iv, iv, AES_BLOCKLEN );
  return;
}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey ( uint8_t round, state_t* state, const uint8_t* RoundKey )
{
  for ( uint8_t i=0U; i<4U; ++i )
  {
    for ( uint8_t j=0U; j<4U; ++j )
    {
      ( *state )[i][j] ^= RoundKey[( round * Nb * 4U ) + ( i * Nb ) + j];
    }
  }
  return;
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes ( state_t* state )
{
  uint8_t i = 0U;
  uint8_t j = 0U;
  for ( i=0U; i<4U; ++i )
  {
    for ( j=0U; j<4U; ++j )
    {
      ( *state )[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
  return;
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows ( state_t* state )
{
  uint8_t temp = 0U;

  // Rotate first row 1 columns to left  
  temp             = (*state)[0U][1U];
  (*state)[0U][1U] = (*state)[1U][1U];
  (*state)[1U][1U] = (*state)[2U][1U];
  (*state)[2U][1U] = (*state)[3U][1U];
  (*state)[3U][1U] = temp;
  // Rotate second row 2 columns to left  
  temp             = (*state)[0U][2U];
  (*state)[0U][2U] = (*state)[2U][2U];
  (*state)[2U][2U] = temp;

  temp             = (*state)[1U][2U];
  (*state)[1U][2U] = (*state)[3U][2U];
  (*state)[3U][2U] = temp;
  // Rotate third row 3 columns to left
  temp             = (*state)[0U][3U];
  (*state)[0U][3U] = (*state)[3U][3U];
  (*state)[3U][3U] = (*state)[2U][3U];
  (*state)[2U][3U] = (*state)[1U][3U];
  (*state)[1U][3U] = temp;
  return;
}

static uint8_t xtime(uint8_t x)
{
  return ( ( x << 1U ) ^ ( ( ( x >> 7U ) & 1U) * 0x1BU ) );
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns ( state_t* state )
{
  uint8_t Tmp = 0U;
  uint8_t Tm  = 0U;
  uint8_t t   = 0U;
  for ( uint8_t i=0U; i<4U; ++i )
  {  
    t   = ( *state )[i][0U];
    Tmp = ( *state )[i][0U] ^ ( *state )[i][1U] ^ ( *state )[i][2U] ^ ( *state )[i][3U];
    Tm  = ( *state )[i][0U] ^ ( *state )[i][1U];
    Tm  = xtime( Tm );
    ( *state )[i][0U] ^= Tm ^ Tmp;
    Tm  = ( *state )[i][1U] ^ ( *state )[i][2U];
    Tm  = xtime( Tm );
    ( *state )[i][1U] ^= Tm ^ Tmp;
    Tm  = ( *state )[i][2U] ^ ( *state )[i][3U];
    Tm  = xtime( Tm );
    ( *state )[i][2U] ^= Tm ^ Tmp ;
    Tm  = ( *state )[i][3U] ^ t ;
    Tm  = xtime( Tm );
    ( *state )[i][3U] ^= Tm ^ Tmp ;
  }
  return;
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if ( defined( CBC ) && CBC == 1U ) || ( defined( ECB ) && ECB == 1U )
// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns ( state_t* state )
{
  uint8_t i = 0U;
  uint8_t a = 0U;
  uint8_t b = 0U;
  uint8_t c = 0U;
  uint8_t d = 0U;
  for ( i=0U; i<4U; ++i )
  { 
    a = ( *state )[i][0U];
    b = ( *state )[i][1U];
    c = ( *state )[i][2U];
    d = ( *state )[i][3U];

    ( *state )[i][0U] = Multiply( a, 0x0eU ) ^ Multiply( b, 0x0bU ) ^ Multiply( c, 0x0dU ) ^ Multiply( d, 0x09U );
    ( *state )[i][1U] = Multiply( a, 0x09U ) ^ Multiply( b, 0x0eU ) ^ Multiply( c, 0x0bU ) ^ Multiply( d, 0x0dU );
    ( *state )[i][2U] = Multiply( a, 0x0dU ) ^ Multiply( b, 0x09U ) ^ Multiply( c, 0x0eU ) ^ Multiply( d, 0x0bU );
    ( *state )[i][3U] = Multiply( a, 0x0bU ) ^ Multiply( b, 0x0dU ) ^ Multiply( c, 0x09U ) ^ Multiply( d, 0x0eU );
  }
  return;
}
// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes ( state_t* state )
{
  for ( uint8_t i=0U; i<4U; ++i )
  {
    for ( uint8_t j=0U; j<4U; ++j )
    {
      ( *state )[j][i] = getSBoxInvert( ( *state )[j][i] );
    }
  }
  return;
}

static void InvShiftRows ( state_t* state )
{
  // Rotate first row 1 columns to right  
  uint8_t temp = ( *state )[3U][1U];
  ( *state )[3U][1U] = ( *state )[2U][1U];
  ( *state )[2U][1U] = ( *state )[1U][1U];
  ( *state )[1U][1U] = ( *state )[0U][1U];
  ( *state )[0U][1U] = temp;

  // Rotate second row 2 columns to right 
  temp = ( *state )[0U][2U];
  ( *state )[0U][2U] = ( *state )[2U][2U];
  ( *state )[2U][2U] = temp;

  temp = ( *state )[1U][2U];
  ( *state )[1U][2U] = ( *state )[3U][2U];
  ( *state )[3U][2U] = temp;

  // Rotate third row 3 columns to right
  temp = ( *state )[0U][3U];
  ( *state )[0U][3U] = ( *state )[1U][3U];
  ( *state )[1U][3U] = ( *state )[2U][3U];
  ( *state )[2U][3U] = ( *state )[3U][3U];
  ( *state )[3U][3U] = temp;
  return;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher ( state_t* state, const uint8_t* RoundKey )
{
  uint8_t round = 0U;
  // Add the First round key to the state before starting the rounds.
  AddRoundKey( 0U, state, RoundKey );
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for ( round=1U; ; ++round )
  {
    SubBytes( state );
    ShiftRows( state );
    if ( round == Nr )
    {
      break;
    }
    MixColumns( state );
    AddRoundKey( round, state, RoundKey );
  }
  // Add round key to last round
  AddRoundKey( Nr, state, RoundKey );
  return;
}

#if ( defined( CBC ) && CBC == 1U ) || ( defined( ECB ) && ECB == 1U )
static void InvCipher ( state_t* state, const uint8_t* RoundKey )
{
  uint8_t round = 0U;
  // Add the First round key to the state before starting the rounds.
  AddRoundKey( Nr, state, RoundKey );
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for ( round=( Nr - 1U ); ; --round )
  {
    InvShiftRows( state );
    InvSubBytes( state );
    AddRoundKey( round, state, RoundKey );
    if ( round == 0U )
    {
      break;
    }
    InvMixColumns( state );
  }
  return;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined( ECB ) && ( ECB == 1U )
void AES_ECB_encrypt ( const struct AES_ctx* ctx, uint8_t* buf )
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher( ( state_t* )buf, ctx->RoundKey );
  return;
}

void AES_ECB_decrypt ( const struct AES_ctx* ctx, uint8_t* buf )
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher( ( state_t* )buf, ctx->RoundKey );
  return;
}
#endif // #if defined(ECB) && (ECB == 1)

#if defined( CBC ) && ( CBC == 1U )
static void XorWithIv ( uint8_t* buf, const uint8_t* Iv )
{
  for ( uint8_t i=0U; i<AES_BLOCKLEN; ++i ) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
  return;
}

void AES_CBC_encrypt_buffer ( struct AES_ctx *ctx, uint8_t* buf, uint32_t length )
{
  uint8_t* Iv = ctx->Iv;
  for ( uintptr_t i=0U; i<length; i+=AES_BLOCKLEN )
  {
    XorWithIv( buf, Iv );
    Cipher( ( state_t* )buf, ctx->RoundKey );
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  memcpy( ctx->Iv, Iv, AES_BLOCKLEN );
  return;
}

void AES_CBC_decrypt_buffer ( struct AES_ctx* ctx, uint8_t* buf,  uint32_t length )
{
  uint8_t storeNextIv[AES_BLOCKLEN];
  for ( uintptr_t i=0U; i<length; i+=AES_BLOCKLEN )
  {
    memcpy( storeNextIv, buf, AES_BLOCKLEN );
    InvCipher( ( state_t* )buf, ctx->RoundKey );
    XorWithIv( buf, ctx->Iv );
    memcpy( ctx->Iv, storeNextIv, AES_BLOCKLEN );
    buf += AES_BLOCKLEN;
  }
  return;
}
#endif // #if defined(CBC) && (CBC == 1)



#if defined ( CTR ) && ( CTR == 1U )
/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer ( struct AES_ctx* ctx, uint8_t* buf, uint32_t length )
{
  uint8_t buffer[AES_BLOCKLEN];
  int32_t bi = 0U;
  for ( uint32_t i=0U, bi=AES_BLOCKLEN; i<length; ++i, ++bi)
  {
    if ( bi == AES_BLOCKLEN ) /* we need to regen xor compliment in buffer */
    {
      memcpy( buffer, ctx->Iv, AES_BLOCKLEN );
      Cipher( ( state_t* )buffer, ctx->RoundKey );
      /* Increment Iv and handle overflow */
      for ( bi=(AES_BLOCKLEN - 1U); bi>=0U; --bi )
      {
	/* inc will overflow */
        if ( ctx->Iv[bi] == 255U )
        {
          ctx->Iv[bi] = 0U;
          continue;
        } 
        ctx->Iv[bi] += 1U;
        break;   
      }
      bi = 0U;
    }
    buf[i] = ( buf[i] ^ buffer[bi] );
  }
  return;
}
#endif // #if defined(CTR) && (CTR == 1)

