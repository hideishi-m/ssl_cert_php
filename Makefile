SRCS := $(wildcard src/include/*.php) makephar.php
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

test: $(TARGETS)
	@echo ssl_cert_discovery
	./ssl_cert_discovery | jq
	@echo ssl_cert_check /etc/letsencrypt/live/balthasar.magisystem.net/fullchain.pem
	./ssl_cert_check /etc/letsencrypt/live/balthasar.magisystem.net/fullchain.pem | jq
	@echo ssl_cert_check /etc/pki/tls/certs/localhost.crt
	./ssl_cert_check /etc/pki/tls/certs/localhost.crt | jq
	@echo ssl_cert_check /var/lib/zabbix/certs/zabbix.crt
	./ssl_cert_check /var/lib/zabbix/certs/zabbix.crt | jq
	@echo ssl_cert_verify /etc/letsencrypt/live/balthasar.magisystem.net/fullchain.pem
	./ssl_cert_verify /etc/letsencrypt/live/balthasar.magisystem.net/fullchain.pem | jq
	@echo ssl_cert_verify /etc/pki/tls/certs/localhost.crt
	./ssl_cert_verify /etc/pki/tls/certs/localhost.crt /etc/pki/tls/certs/localhost.crt | jq
	@echo ssl_cert_verify /var/lib/zabbix/certs/zabbix.crt
	./ssl_cert_verify /var/lib/zabbix/certs/zabbix.crt /var/lib/zabbix/certs/zabbix.crt | jq
