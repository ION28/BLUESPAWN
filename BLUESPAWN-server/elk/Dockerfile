FROM sebp/elk:latest

# Enable security in Elasticsearch
RUN echo "xpack.security.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
RUN	echo "xpack.security.transport.ssl.enabled: true" >> /etc/elasticsearch/elasticsearch.yml

# Copy in additional startup scripts
RUN sed -i '$ d' /usr/local/bin/start.sh
COPY extraStart.sh /usr/local/bin/extraStart.sh
RUN cat /usr/local/bin/extraStart.sh >> /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]