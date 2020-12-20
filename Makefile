CC = gcc
CFLAGS = -I /usr/include/pcap -I ./include
LD = ld
LDFLAGS = -lpcap
OBJ = arp_spoof.o arp.o
EXE = arp_spoof

.PHONY: arp clean

arp: $(EXE)

clean:
	rm $(EXE) $(OBJ) $(LDFLAGS)
    
$(EXE) : $(OBJ) 
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

arp.o : src/arp.c
	$(CC) -c -o $@ $< $(CFLAGS) 

arp_spoof.o : src/arp_spoof.c
	$(CC) -c -o $@ $< $(CFLAGS)
