################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (14.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
C:/Users/Lenovo/STM32Cube/Repository/STM32Cube_FW_L4_V1.18.2/Drivers/BSP/STM32L4xx_Nucleo_32/stm32l4xx_nucleo_32.c 

OBJS += \
./Drivers/BSP/STM32L4xx_Nucleo/stm32l4xx_nucleo_32.o 

C_DEPS += \
./Drivers/BSP/STM32L4xx_Nucleo/stm32l4xx_nucleo_32.d 


# Each subdirectory must supply rules for building sources it contributes
Drivers/BSP/STM32L4xx_Nucleo/stm32l4xx_nucleo_32.o: C:/Users/Lenovo/STM32Cube/Repository/STM32Cube_FW_L4_V1.18.2/Drivers/BSP/STM32L4xx_Nucleo_32/stm32l4xx_nucleo_32.c Drivers/BSP/STM32L4xx_Nucleo/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DDEBUG -DUSE_NUCLEO_32 -DUSE_HAL_DRIVER -DSTM32L432xx -c -I../Core/Inc -IC:/Users/Lenovo/STM32Cube/Repository/STM32Cube_FW_L4_V1.18.2/Drivers/STM32L4xx_HAL_Driver/Inc -IC:/Users/Lenovo/STM32Cube/Repository/STM32Cube_FW_L4_V1.18.2/Drivers/STM32L4xx_HAL_Driver/Inc/Legacy -IC:/Users/Lenovo/STM32Cube/Repository/STM32Cube_FW_L4_V1.18.2/Drivers/BSP/STM32L4xx_Nucleo_32 -IC:/Users/Lenovo/STM32Cube/Repository/STM32Cube_FW_L4_V1.18.2/Drivers/CMSIS/Device/ST/STM32L4xx/Include -IC:/Users/Lenovo/STM32Cube/Repository/STM32Cube_FW_L4_V1.18.2/Drivers/CMSIS/Include -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Drivers-2f-BSP-2f-STM32L4xx_Nucleo

clean-Drivers-2f-BSP-2f-STM32L4xx_Nucleo:
	-$(RM) ./Drivers/BSP/STM32L4xx_Nucleo/stm32l4xx_nucleo_32.cyclo ./Drivers/BSP/STM32L4xx_Nucleo/stm32l4xx_nucleo_32.d ./Drivers/BSP/STM32L4xx_Nucleo/stm32l4xx_nucleo_32.o ./Drivers/BSP/STM32L4xx_Nucleo/stm32l4xx_nucleo_32.su

.PHONY: clean-Drivers-2f-BSP-2f-STM32L4xx_Nucleo

