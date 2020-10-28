/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : usbd_dfu_if.c
  * @brief          : Usb device for Download Firmware Update.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2020 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under Ultimate Liberty license
  * SLA0044, the "License"; You may not use this file except in compliance with
  * the License. You may obtain a copy of the License at:
  *                             www.st.com/SLA0044
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "usbd_dfu_if.h"

/* USER CODE BEGIN INCLUDE */
#include "aes.h"
/* USER CODE END INCLUDE */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/

/* USER CODE BEGIN PV */
/* Private variables ---------------------------------------------------------*/

/* USER CODE END PV */

/** @addtogroup STM32_USB_OTG_DEVICE_LIBRARY
  * @brief Usb device.
  * @{
  */

/** @defgroup USBD_DFU
  * @brief Usb DFU device module.
  * @{
  */

/** @defgroup USBD_DFU_Private_TypesDefinitions
  * @brief Private types.
  * @{
  */

/* USER CODE BEGIN PRIVATE_TYPES */

/* USER CODE END PRIVATE_TYPES */

/**
  * @}
  */

/** @defgroup USBD_DFU_Private_Defines
  * @brief Private defines.
  * @{
  */

#define FLASH_DESC_STR    "@Internal Flash/0x08008000/02*016Kg,01*064Kg,07*128Kg"

/* USER CODE BEGIN PRIVATE_DEFINES */

/* USER CODE END PRIVATE_DEFINES */

/**
  * @}
  */

/** @defgroup USBD_DFU_Private_Macros
  * @brief Private macros.
  * @{
  */

/* USER CODE BEGIN PRIVATE_MACRO */

/* USER CODE END PRIVATE_MACRO */

/**
  * @}
  */

/** @defgroup USBD_DFU_Private_Variables
  * @brief Private variables.
  * @{
  */

/* USER CODE BEGIN PRIVATE_VARIABLES */
#if ( ENCRYPTION_ENB > 0 )
  static const  uint8_t key[AES_KEYLEN]  = { 0x83, 0xF7, 0x79, 0x7F, 0x52, 0x1E, 0x37, 0xA2, 0x6B, 0xAF, 0xBB, 0xD0, 0x41, 0x77, 0x9A, 0xB5 };
  static const  uint8_t iv[AES_BLOCKLEN] = { 0x49, 0x60, 0x7B, 0x42, 0x55, 0xE6, 0xE9, 0x4B, 0x3C, 0xC7, 0x76, 0xFB, 0x06, 0x67, 0xA9, 0xF2 };
  static struct AES_ctx ctx              = { 0U };
#endif
/* USER CODE END PRIVATE_VARIABLES */

/**
  * @}
  */

/** @defgroup USBD_DFU_Exported_Variables
  * @brief Public variables.
  * @{
  */

extern USBD_HandleTypeDef hUsbDeviceFS;

/* USER CODE BEGIN EXPORTED_VARIABLES */

/* USER CODE END EXPORTED_VARIABLES */

/**
  * @}
  */

/** @defgroup USBD_DFU_Private_FunctionPrototypes
  * @brief Private functions declaration.
  * @{
  */

static uint16_t MEM_If_Init_FS(void);
static uint16_t MEM_If_Erase_FS(uint32_t Add);
static uint16_t MEM_If_Write_FS(uint8_t *src, uint8_t *dest, uint32_t Len);
static uint8_t *MEM_If_Read_FS(uint8_t *src, uint8_t *dest, uint32_t Len);
static uint16_t MEM_If_DeInit_FS(void);
static uint16_t MEM_If_GetStatus_FS(uint32_t Add, uint8_t Cmd, uint8_t *buffer);

/* USER CODE BEGIN PRIVATE_FUNCTIONS_DECLARATION */

/* USER CODE END PRIVATE_FUNCTIONS_DECLARATION */

/**
  * @}
  */

#if defined ( __ICCARM__ ) /* IAR Compiler */
  #pragma data_alignment=4
#endif
__ALIGN_BEGIN USBD_DFU_MediaTypeDef USBD_DFU_fops_FS __ALIGN_END =
{
   (uint8_t*)FLASH_DESC_STR,
    MEM_If_Init_FS,
    MEM_If_DeInit_FS,
    MEM_If_Erase_FS,
    MEM_If_Write_FS,
    MEM_If_Read_FS,
    MEM_If_GetStatus_FS
};

/* Private functions ---------------------------------------------------------*/
/**
  * @brief  Memory initialization routine.
  * @retval USBD_OK if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Init_FS(void)
{
  /* USER CODE BEGIN 0 */
  #if ( ENCRYPTION_ENB > 0 )
    AES_init_ctx_iv( &ctx, key, iv );
  #endif
  HAL_StatusTypeDef flashStatus = HAL_ERROR;
  while ( flashStatus != HAL_OK )
  {
    flashStatus = HAL_FLASH_Unlock();
  }
  return ( USBD_OK );
  /* USER CODE END 0 */
}

/**
  * @brief  De-Initializes Memory
  * @retval USBD_OK if operation is successful, MAL_FAIL else
  */
uint16_t MEM_If_DeInit_FS(void)
{
  /* USER CODE BEGIN 1 */
  HAL_StatusTypeDef flashStatus = HAL_ERROR;
  while ( flashStatus != HAL_OK )
  {
    flashStatus = HAL_FLASH_Lock();
  }
  return ( USBD_OK );
  /* USER CODE END 1 */
}

/**
  * @brief  Erase sector.
  * @param  Add: Address of sector to be erased.
  * @retval 0 if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Erase_FS(uint32_t Add)
{
  /* USER CODE BEGIN 2 */
  uint32_t               pageError = 0U;
  HAL_StatusTypeDef      status    = HAL_ERROR;
  USBD_StatusTypeDef     res       = USBD_FAIL;
  FLASH_EraseInitTypeDef eraseInit;

  if ( Add > BOOTLADER_SIZE ) {
    eraseInit.TypeErase    = FLASH_TYPEERASE_SECTORS;
    eraseInit.Banks        = FLASH_BANK_1;
    eraseInit.Sector       = GET_SECTOR( Add );
    eraseInit.NbSectors    = 1U;
    eraseInit.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    status = HAL_FLASHEx_Erase( &eraseInit, &pageError );
    if ( status == HAL_OK )
    {
      res = USBD_OK;
    }
  }
  else
  {
    res = USBD_OK;
  }
  return res;
  /* USER CODE END 2 */
}

/**
  * @brief  Memory write routine.
  * @param  src: Pointer to the source buffer. Address to be written to.
  * @param  dest: Pointer to the destination buffer.
  * @param  Len: Number of data to be written (in bytes).
  * @retval USBD_OK if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Write_FS( uint8_t *src, uint8_t *dest, uint32_t Len )
{
  /* USER CODE BEGIN 3 */
  uint32_t           i      = 0U;
  USBD_StatusTypeDef result = USBD_FAIL;

  #if ( ENCRYPTION_ENB > 0 )
    AES_CBC_decrypt_buffer( &ctx, src, Len );
  #endif
  for ( i=0U; i<Len; i+=4U )
  {
	if ( ( uint32_t )( dest + i ) > BOOTLADER_SIZE )
	{
      if ( HAL_FLASH_Program( FLASH_TYPEPROGRAM_WORD, ( uint32_t )( dest + i ), *( uint32_t* )( src + i ) ) == HAL_OK )
      {
        if ( *( uint32_t* )( src + i ) != *( uint32_t* )( dest + i ) )
        {
          result = USBD_FAIL;
          break;
        }
        else
        {
          result = USBD_OK;
        }
      }
      else
      {
        result = USBD_FAIL;
        break;
      }
	}
  }
  return result;
  /* USER CODE END 3 */
}

/**
  * @brief  Memory read routine.
  * @param  src: Pointer to the source buffer. Address to be written to.
  * @param  dest: Pointer to the destination buffer.
  * @param  Len: Number of data to be read (in bytes).
  * @retval Pointer to the physical address where data should be read.
  */
uint8_t *MEM_If_Read_FS(uint8_t *src, uint8_t *dest, uint32_t Len)
{
  /* Return a valid address to avoid HardFault */
  /* USER CODE BEGIN 4 */
  #if ( READING_ENB > 0 )
    uint32_t i    = 0U;
    uint8_t *psrc = src;

    for ( i=0U; i<Len; i++ )
    {
      dest[i] = *psrc++;
    }
    return ( uint8_t* )( dest );
  #else
    return (USBD_OK);
  #endif
  /* USER CODE END 4 */
}

/**
  * @brief  Get status routine
  * @param  Add: Address to be read from
  * @param  Cmd: Number of data to be read (in bytes)
  * @param  buffer: used for returning the time necessary for a program or an erase operation
  * @retval USBD_OK if operation is successful
  */
uint16_t MEM_If_GetStatus_FS(uint32_t Add, uint8_t Cmd, uint8_t *buffer)
{
  /* USER CODE BEGIN 5 */
  switch (Cmd)
  {
    case DFU_MEDIA_PROGRAM:

    break;

    case DFU_MEDIA_ERASE:
    default:

    break;
  }
  return (USBD_OK);
  /* USER CODE END 5 */
}

/* USER CODE BEGIN PRIVATE_FUNCTIONS_IMPLEMENTATION */

/* USER CODE END PRIVATE_FUNCTIONS_IMPLEMENTATION */

/**
  * @}
  */

/**
  * @}
  */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
