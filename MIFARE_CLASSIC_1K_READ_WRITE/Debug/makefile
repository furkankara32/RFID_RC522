################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (13.3.rel1)
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include Drivers/STM32F7xx_HAL_Driver/Src/subdir.mk
-include Core/Startup/subdir.mk
-include Core/Src/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(S_DEPS)),)
-include $(S_DEPS)
endif
ifneq ($(strip $(S_UPPER_DEPS)),)
-include $(S_UPPER_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

OPTIONAL_TOOL_DEPS := \
$(wildcard ../makefile.defs) \
$(wildcard ../makefile.init) \
$(wildcard ../makefile.targets) \


BUILD_ARTIFACT_NAME := MIFARE_CLASSIC_1K_READ_WRITE
BUILD_ARTIFACT_EXTENSION := elf
BUILD_ARTIFACT_PREFIX :=
BUILD_ARTIFACT := $(BUILD_ARTIFACT_PREFIX)$(BUILD_ARTIFACT_NAME)$(if $(BUILD_ARTIFACT_EXTENSION),.$(BUILD_ARTIFACT_EXTENSION),)

# Add inputs and outputs from these tool invocations to the build variables 
EXECUTABLES += \
MIFARE_CLASSIC_1K_READ_WRITE.elf \

MAP_FILES += \
MIFARE_CLASSIC_1K_READ_WRITE.map \

SIZE_OUTPUT += \
default.size.stdout \

OBJDUMP_LIST += \
MIFARE_CLASSIC_1K_READ_WRITE.list \


# All Target
all: main-build

# Main-build Target
main-build: MIFARE_CLASSIC_1K_READ_WRITE.elf secondary-outputs

# Tool invocations
MIFARE_CLASSIC_1K_READ_WRITE.elf MIFARE_CLASSIC_1K_READ_WRITE.map: $(OBJS) $(USER_OBJS) C:\Users\furkan\ArsiaElectronic\MIFARE_CLASSIC_1K_READ_WRITE\STM32F767ZITX_FLASH.ld makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-gcc -o "MIFARE_CLASSIC_1K_READ_WRITE.elf" @"objects.list" $(USER_OBJS) $(LIBS) -mcpu=cortex-m7 -T"C:\Users\furkan\ArsiaElectronic\MIFARE_CLASSIC_1K_READ_WRITE\STM32F767ZITX_FLASH.ld" --specs=nosys.specs -Wl,-Map="MIFARE_CLASSIC_1K_READ_WRITE.map" -Wl,--gc-sections -static --specs=nano.specs -mfpu=fpv5-d16 -mfloat-abi=hard -mthumb -Wl,--start-group -lc -lm -Wl,--end-group
	@echo 'Finished building target: $@'
	@echo ' '

default.size.stdout: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-size  $(EXECUTABLES)
	@echo 'Finished building: $@'
	@echo ' '

MIFARE_CLASSIC_1K_READ_WRITE.list: $(EXECUTABLES) makefile objects.list $(OPTIONAL_TOOL_DEPS)
	arm-none-eabi-objdump -h -S $(EXECUTABLES) > "MIFARE_CLASSIC_1K_READ_WRITE.list"
	@echo 'Finished building: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) MIFARE_CLASSIC_1K_READ_WRITE.elf MIFARE_CLASSIC_1K_READ_WRITE.list MIFARE_CLASSIC_1K_READ_WRITE.map default.size.stdout
	-@echo ' '

secondary-outputs: $(SIZE_OUTPUT) $(OBJDUMP_LIST)

fail-specified-linker-script-missing:
	@echo 'Error: Cannot find the specified linker script. Check the linker settings in the build configuration.'
	@exit 2

warn-no-linker-script-specified:
	@echo 'Warning: No linker script specified. Check the linker settings in the build configuration.'

.PHONY: all clean dependents main-build fail-specified-linker-script-missing warn-no-linker-script-specified

-include ../makefile.targets
