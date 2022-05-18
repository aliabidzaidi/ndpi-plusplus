include /usr/local/etc/PcapPlusPlus.mk


# nDPI includes
SRCHOME = /opt/nDPI/src
CFLAGS=-g -fPIC -DPIC -I$(SRCHOME)/include -g -O2
LIBNDPI=$(SRCHOME)/lib/libndpi.a
LDFLAGS=$(LIBNDPI) -lpcap -lpthread -lm

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) $(CFLAGS) -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++  $(CFLAGS) $(LDFLAGS) -o ndpi-plusplus main.o $(PCAPPP_LIBS)

debug:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -g -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -g -static-libstdc++ -o ndpi-plusplus main.o $(PCAPPP_LIBS)


# Clean Target
clean:
	rm main.o
	rm ndpi-plusplus
