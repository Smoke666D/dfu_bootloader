#include "tests.h"
#include "unity.h"

int main ( void )
{
  UnityBegin( "" );
  test_aes();
  UnityEnd();
  return 0U;
}