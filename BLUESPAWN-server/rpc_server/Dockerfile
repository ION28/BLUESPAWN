FROM golang:1.15

ENV PROTOC_VER 3.13.0
ENV PROTOC_GEN_GO_VER 1.4.0

# Install dependencies
RUN apt-get update --fix-missing && apt-get install -y \
    zip unzip build-essential curl wget

# Install protoc for gRPC
WORKDIR /tmp
RUN wget -O protoc-${PROTOC_VER}-linux-x86_64.zip https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VER}/protoc-${PROTOC_VER}-linux-x86_64.zip \
    && unzip protoc-${PROTOC_VER}-linux-x86_64.zip \
    && cp -vv ./bin/protoc /usr/local/bin

# Install go get
RUN wget -O protoc-gen-go.tar.gz https://github.com/golang/protobuf/archive/v${PROTOC_GEN_GO_VER}.tar.gz \
  && tar xvf protoc-gen-go.tar.gz \
  && cd protobuf-${PROTOC_GEN_GO_VER} \
  && make install

# Install gRPC
RUN go get google.golang.org/grpc

# Change to /usr/src
WORKDIR /usr/src

# Copy BLUESPAWN source code into container
COPY ./ ./

# Compile Protobuf 
RUN protoc --go_out="plugins=grpc:$GOPATH/src" ./BLUESPAWN-common/bluespawnpb/bluespawn.proto

# Build and start rpc_server
RUN cd ./BLUESPAWN-server/rpc_server && \
    go build

ENTRYPOINT ["./BLUESPAWN-server/rpc_server/rpc_server"]
