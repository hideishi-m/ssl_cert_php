SRCS := $(wildcard src/include/*.php)
TARGETS := ssl_cert_discovery ssl_cert_check ssl_cert_verify

all: $(TARGETS)

ssl_cert_discovery: src/ssl_cert_discovery.php $(SRCS)
	podman run --rm -v /home/hideishi/php:/usr/src:rw -it makephar $@

ssl_cert_check: src/ssl_cert_check.php $(SRCS)
	podman run --rm -v /home/hideishi/php:/usr/src:rw -it makephar $@

ssl_cert_verify: src/ssl_cert_verify.php $(SRCS)
	podman run --rm -v /home/hideishi/php:/usr/src:rw -it makephar $@

clean:
	rm -rf $(TARGETS)
