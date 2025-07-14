CFLAGS=-g -W -Wall -Wundef 
LIBS= -lauplugin -lauparse -laudit
all:
	gcc $(CFLAGS) auplugin-example.c -o auplugin-example $(LIBS)

clean:
	rm -f auplugin-example *.o
