include /usr/local/etc/PcapPlusPlus.mk

# nDPI includes
NDPI_INCLUDES=-I/opt/nDPI/src/include

# All Target
all:
	g++ -fPIC -DPIC -g -I/opt/nDPI/src/include  -W -Wall -Wno-unused-parameter -Wno-unused-function -Wno-address-of-packed-member -g -O2  -pthread   -c -o main.o main.cpp
	g++ -fPIC -DPIC -g -I/opt/nDPI/src/include  -W -Wall -Wno-unused-parameter -Wno-unused-function -Wno-address-of-packed-member -g -O2  -pthread   -c -o main.o main.cpp

# Clean Target
clean:
	rm main.o
	rm ndpi-plusplus
