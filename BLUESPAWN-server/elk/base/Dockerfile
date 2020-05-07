FROM sebp/elk:latest

# Install certificates
COPY configureSSL.sh /certs/configureSSL.sh
COPY runCertGen.sh /certs/runCertGen.sh
COPY createCA.sh /certs/createCA.sh
COPY createNodeCerts.sh /certs/createNodeCerts.sh
COPY configurePasswords.sh configurePasswords.sh
RUN set -ex; \
	chmod +x /certs/configureSSL.sh; \
	chmod +x /certs/runCertGen.sh; \
	chmod +x /certs/createCA.sh; \
	chmod +x /certs/createNodeCerts.sh; \
	/certs/configureSSL.sh; \

# Prepare for password configuration passwords
	chmod +x configurePasswords.sh

CMD ["/bin/bash", "-c", "echo built"]