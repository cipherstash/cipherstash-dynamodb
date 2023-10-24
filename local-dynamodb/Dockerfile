FROM amazon/dynamodb-local

WORKDIR /home/dynamodblocal/

USER root
RUN yum update --assumeyes --quiet \
    && yum install --assumeyes --quiet awscli \
    && yum clean all \
    && rm -rf /var/cache/yum
RUN mkdir /data
COPY entrypoint.sh /entrypoint.sh
RUN chown dynamodblocal:dynamodblocal /data /entrypoint.sh

USER dynamodblocal
ENTRYPOINT /entrypoint.sh
