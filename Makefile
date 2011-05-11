# steki@verat.net
#
# Compile with debug code...
#CC = gcc -g -Wall -DDEBUG
#
#
# Compile without debug code...
CC = gcc -g -Wall
#
#
LDFLAGS = -lldap -llber -lcrypt
PROGRAMS = fchangepass changepass checkpass
SOURCES = lpass.c fchangepass.c changepass.c checkpass.c
OBJECTS = lpass.o

all: programs showit
all-strip: programs stripit showit

programs:  clean $(OBJECTS) fchangepass.o changepass.o checkpass.o 
	$(CC) -o changepass $(OBJECTS) changepass.o $(LDFLAGS)
	$(CC) -o fchangepass $(OBJECTS) fchangepass.o $(LDFLAGS)
	$(CC) -o checkpass $(OBJECTS) checkpass.o $(LDFLAGS)

showit:
	@echo ""
	@echo "		***Programs***"
	@ls -l $(PROGRAMS)
	@echo "		**************"

stripit:
	strip $(PROGRAMS)

in:
	indent $(SOURCES)

clean:
	rm -f $(OBJECTS) *~ $(PROGRAMS) fchangepass.o changepass.o checkpass.o

SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<
