/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : usbd_dfu_if.h
  * @brief          : Header for usbd_dfu_if.c file.
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

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __USBD_DFU_IF_H__
#define __USBD_DFU_IF_H__

#ifdef __cplusplus
 extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "usbd_dfu.h"

/* USER CODE BEGIN INCLUDE */

/* USER CODE END INCLUDE */

/** @addtogroup STM32_USB_DEVICE_LIBRARY
  * @brief For Usb device.
  * @{
  */

/** @defgroup USBD_MEDIA USBD_MEDIA
  * @brief Header file for the usbd_dfu_if.c file.
  * @{
  */

/** @defgroup USBD_MEDIA_Exported_Defines USBD_MEDIA_Exported_Defines
  * @brief Defines.
  * @{
  */

/* USER CODE BEGIN EXPORTED_DEFINES */
#define BOOTLADER_SIZE 	0x08007FFFU
#define APP_ADDRESS    	0x08008000U
#define READING_ENB     0U
/* USER CODE END EXPORTED_DEFINES */

/**
  * @}
  */

/** @defgroup USBD_MEDIA_Exported_Types USBD_MEDIA_Exported_Types
  * @brief Types.
  * @{
  */

/* USER CODE BEGIN EXPORTED_TYPES */

/* USER CODE END EXPORTED_TYPES */

/**
  * @}
  */

/** @defgroup USBD_MEDIA_Exported_Macros USBD_MEDIA_Exported_Macros
  * @brief Aliases.
  * @{
  */

/* USER CODE BEGIN EXPORTED_MACRO */
#define GET_SECTOR( adr )	 ( ( adr < 0x08003FFFU )?FLASH_SECTOR_0:( ( adr < 0x08007FFFU )?FLASH_SECTOR_1:( ( adr < 0x0800BFFFU )?FLASH_SECTOR_2:( ( adr < 0x0800FFFFU )?FLASH_SECTOR_3:( ( adr < 0x0801FFFFU )?FLASH_SECTOR_4:( ( adr < 0x0803FFFFU )?FLASH_SECTOR_5:( ( adr < 0x0805FFFFU )?FLASH_SECTOR_6:( ( adr < 0x0807FFFFU )?FLASH_SECTOR_7:( ( adr < 0x0809FFFFU )?FLASH_SECTOR_8:( ( adr < 0x080BFFFFU )?FLASH_SECTOR_9:( ( adr < 0x080DFFFFU )?FLASH_SECTOR_10:FLASH_SECTOR_11 ) ) ) ) ) ) ) ) ) ) )
/* USER CODE END EXPORTED_MACRO */

/**
  * @}
  */

/** @defgroup USBD_MEDIA_Exported_Variables USBD_MEDIA_Exported_Variables
  * @brief Public variables.
  * @{
  */

/** MEDIA Interface callback. */
extern USBD_DFU_MediaTypeDef USBD_DFU_fops_FS;

/* USER CODE BEGIN EXPORTED_VARIABLES */

/* USER CODE END EXPORTED_VARIABLES */

/**
  * @}
  */

/** @defgroup USBD_MEDIA_Exported_FunctionsPrototype USBD_MEDIA_Exported_FunctionsPrototype
  * @brief Public functions declaration.
  * @{
  */

/* USER CODE BEGIN EXPORTED_FUNCTIONS */

/* USER CODE END EXPORTED_FUNCTIONS */

/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

#ifdef __cplusplus
}
#endif

#endif /* __USBD_DFU_IF_H__ */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
