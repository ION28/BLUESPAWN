FROM sebp/elk:latest

# Enable security in Elasticsearch
RUN echo "xpack.security.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
RUN	echo "xpack.security.transport.ssl.enabled: true" >> /etc/elasticsearch/elasticsearch.yml

# Configure passwords
RUN cp /usr/local/bin/start.sh /usr/local/bin/runElk.sh
RUN sed -i '$ d' /usr/local/bin/runElk.sh
COPY configurePasswords.sh configurePasswords.sh
RUN /usr/local/bin/runElk.sh; chmod +x configurePasswords.sh; ./configurePasswords.sh
RUN rm configurePasswords.sh
RUN rm /usr/local/bin/runElk.sh
RUN service logstash stop
RUN service kibana stop
RUN service elasticsearch stop

CMD ["/usr/local/bin/start.sh"]