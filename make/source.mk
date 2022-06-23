C_SOURCE_LIBS =\
USB_DEVICE/App/usb_device.c \
USB_DEVICE/Target/usbd_conf.c \
USB_DEVICE/App/usbd_desc.c \
USB_DEVICE/App/usbd_dfu_if.c \
Core/Src/stm32f2xx_it.c \
Core/Src/stm32f2xx_hal_msp.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal_pcd_ex.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal_pcd.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_ll_usb.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal_rcc.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal_rcc_ex.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal_cortex.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal_flash.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal_flash_ex.c \
Drivers/STM32F2xx_HAL_Driver/Src/stm32f2xx_hal_gpio.c \
Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_core.c \
Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_ctlreq.c \
Middlewares/ST/STM32_USB_Device_Library/Core/Src/usbd_ioreq.c \
Middlewares/ST/STM32_USB_Device_Library/Class/DFU/Src/usbd_dfu.c \
Core/Src/system_stm32f2xx.c \


C_SOURCES_TEST = \
Unity/unity_config.c \
Unity/unity.c

C_SOURCE_PROJ = \
Core/Src/main.c \
aes/Src/aes.c

C_SOURCES      = $(C_SOURCE_LIBS) $(C_SOURCE_PROJ)
C_TEST_SOURCES = $(C_SOURCES) $(C_SOURCES_TEST)