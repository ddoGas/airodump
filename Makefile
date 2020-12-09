LDLIBS=-lpcap

all: airodump

airodump: main.o getadds.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o