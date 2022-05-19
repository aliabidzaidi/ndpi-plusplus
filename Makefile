include /usr/local/etc/PcapPlusPlus.mk

# nDPI includes
NDPI_LINKER=/opt/nDPI/src/lib/libndpi.a

EXTRAS=-W -Wall -Wno-unused-parameter -Wno-unused-function -Wno-address-of-packed-member -g -O3
EXTRAS2=-W -Wall -Wno-unused-parameter -Wno-unused-function -Wno-address-of-packed-member -g -O3 
# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -g -I/opt/nDPI/src/include -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -fPIC -DPIC -g -I/opt/nDPI/src/include -o ndpi-plusplus main.o $(PCAPPP_LIBS) $(NDPI_LINKER)

# Clean Target
clean:
	rm main.o
	rm ndpi-plusplus
