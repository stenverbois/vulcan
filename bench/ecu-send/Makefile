ID_SM=1

-include ../../Makefile.config

SOURCES             = $(shell ls *.c ../common/*.c)
APP                 = main
FPGA_DEV            = /dev/ttyUSB2

ifdef CAN_DRV_SM
    SOURCES += ../../drivers/sm_mmio_spi.c
endif

OBJECTS             = $(SOURCES:.c=.o) $(LIBVULCAN).o
TARGET              = $(APP).elf
TARGET_NO_MAC       = no_mac_$(TARGET)
TARGET_SIM          = $(APP)_sim.elf
TARGET_SIM_NO_MAC   = no_mac_$(TARGET_SIM)

all: $(TARGET) $(TARGET_SIM)

#custom targets since intra-SM libraries cannot be shared
$(LIBVULCAN).o: $(CAN_AUTH_DIR)/$(LIBVULCAN).c
	$(CC) $(CFLAGS) -c $< -o $@

can-drv.o: ../../drivers/mcp2515.c
	$(CC) $(CFLAGS) -c $< -o $@

can-sim.o: ../../drivers/ican_sim.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET_NO_MAC): $(OBJECTS) can-drv.o
	$(LD) $(LDFLAGS) -o $@ $^

$(TARGET_SIM_NO_MAC): $(OBJECTS) can-sim.o
	$(LD) $(LDFLAGS) -o $@ $^

%.elf: no_mac_%.elf
	$(SANCUS_CRYPTO) $(CRYPTOFLAGS) -o $@ $<

load: $(TARGET) print-sm-key
	$(SANCUS_LOAD) $(LOADFLAGS) $<

sim: $(TARGET_SIM)
	$(SANCUS_SIM) $(SIMFLAGS) --fileio-in ../can-pong.bin --fileio-out ../can-ping.bin $<

print-sm-key: $(TARGET)
	@echo "Module-specific key of $(TARGET) is '$(shell $(SANCUS_CRYPTO) --key $(VENDOR_KEY) --gen-sm-key $(VULCAN_SM) $(TARGET) | xxd -p)'"

clean:
	$(RM) *.elf *.o *.bin *.fst $(OBJECTS)
