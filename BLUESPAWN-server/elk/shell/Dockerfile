FROM elk_base:latest

COPY verify.sh /verify.sh

RUN set -ex; \
	apt install nmap -y; \
	chmod +x verify.sh

CMD ["/bin/bash", "-c", "exit"]