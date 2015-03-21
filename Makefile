CC = gcc
CFLAGS = -g -Wall

all: send recv

send: myportscan_send
recv:  myportscan_recv

myportscan_send: myportscan_send.c
	@echo "Compile send"
	-$(CC) $< -o $@ $(CFLAGS)

myportscan_recv: myportscan_recv.c spoofit.h
	@echo "Compile receive"
	-$(CC) $< -o $@ $(CFLAGS)

debug: CFLAGS += -D DEBUG -D TCP_PKT_DEBUG
debug: send recv
	@echo -e "\e[5;37m Debug mode\e[0m"

clean:
	@echo "Clean up"
	rm -rf myportscan_recv myportscan_send
