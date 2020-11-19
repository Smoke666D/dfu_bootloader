/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2020 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usb_device.h"
#include "usbd_dfu_if.h"
/* Private function prototypes -----------------------------------------------*/
void        SystemClock_Config( void );
static void MX_GPIO_Init( void );

int main ( void )
{
  HAL_Init();
  SystemClock_Config();
  MX_GPIO_Init();
  if ( HAL_GPIO_ReadPin( BOOT1_GPIO_Port, BOOT1_Pin ) == GPIO_PIN_SET )
  {
    MX_USB_DEVICE_Init();
    HAL_GPIO_WritePin( LED_GPIO_Port, LED_Pin, GPIO_PIN_SET );
  }
  else
  {
    uint32_t  jumpAddress = *( __IO uint32_t* )( APP_ADDRESS + 4U );
    pFunction jump        = ( pFunction )jumpAddress;
    HAL_RCC_DeInit();
    HAL_DeInit();
    SysTick->CTRL = 0U;
    SysTick->LOAD = 0U;
    SysTick->VAL  = 0U;
    SCB->VTOR     = APP_ADDRESS;
    __set_MSP( *( __IO uint32_t* ) APP_ADDRESS );
    jump();
  }
  while ( 1U )
  {

  }
}

void SystemClock_Config ( void )
{
  RCC_OscInitTypeDef RCC_OscInitStruct = { 0U };
  RCC_ClkInitTypeDef RCC_ClkInitStruct = { 0U };

  RCC_OscInitStruct.OscillatorType      = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState            = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState        = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource       = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM            = 13U;
  RCC_OscInitStruct.PLL.PLLN            = 195U;
  RCC_OscInitStruct.PLL.PLLP            = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ            = 5U;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  RCC_ClkInitStruct.ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                                     | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if ( HAL_RCC_ClockConfig( &RCC_ClkInitStruct, FLASH_LATENCY_3 ) != HAL_OK )
  {
    Error_Handler();
  }
  return;
}
static void MX_GPIO_Init ( void )
{
  GPIO_InitTypeDef GPIO_InitStruct = { 0U };

  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();

  GPIO_InitStruct.Pin  = BOOT1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init( BOOT1_GPIO_Port, &GPIO_InitStruct );

  HAL_GPIO_WritePin( LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET );

  GPIO_InitStruct.Pin  = LED_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init( LED_GPIO_Port, &GPIO_InitStruct );
  return;
}

void Error_Handler ( void )
{

}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
