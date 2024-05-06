TARGETS=enc_server enc_client dec_server dec_client keygen

.PHONY: all clean
all: $(TARGETS)

clean:
	@rm $(TARGETS) 2>/dev/null

define compile
	gcc $(CPPFLAGS) $(CFLAGS) -o $@ $<
endef

dec_% : CPPFLAGS += -DDEC
dec_%: %.c
	$(compile)
enc_%: %.c
	$(compile)
%: %.c
	$(compile)