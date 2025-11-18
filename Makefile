CC=gcc
CFLAGS=-Iinclude -Wall -Wextra -O2
LDFLAGS=

BIN_DIR ?= bin
PROGS := nm ss client
UTILS=utils/socket_utils.c utils/logger.c

.PHONY: all clean dirs

all: dirs $(addprefix $(BIN_DIR)/,$(PROGS))

$(BIN_DIR)/nm: nameserver/nm_main.c nameserver/nm_registry.c $(UTILS)
	$(CC) $(CFLAGS) -o $@ nameserver/nm_main.c nameserver/nm_registry.c $(UTILS) $(LDFLAGS)

$(BIN_DIR)/ss: storageserver/ss_main.c $(UTILS)
	$(CC) $(CFLAGS) -o $@ storageserver/ss_main.c $(UTILS) $(LDFLAGS) -lpthread

$(BIN_DIR)/client: client/client_main.c $(UTILS)
	$(CC) $(CFLAGS) -o $@ client/client_main.c $(UTILS) $(LDFLAGS)

dirs:
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(addprefix $(BIN_DIR)/,$(PROGS))
	rm -f logs/*.log
