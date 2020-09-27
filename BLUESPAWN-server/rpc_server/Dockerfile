FROM golang:1.15

ENV PROTOC_VER 3.13.0

# Install dependencies
RUN apt-get update --fix-missing && apt-get install -y \
    zip unzip build-essential curl wget

# Install protoc 
WORKDIR /tmp
RUN wget -O protoc-${PROTOC_VER}-linux-x86_64.zip https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VER}/protoc-${PROTOC_VER}-linux-x86_64.zip \
    && unzip protoc-${PROTOC_VER}-linux-x86_64.zip \
    && cp -vv ./bin/protoc /usr/local/bin

# Install Go Protocol Buffers plugin
RUN go get -u google.golang.org/protobuf/cmd/protoc-gen-go && go install google.golang.org/protobuf/cmd/protoc-gen-go

# Install gRPC
RUN go get -u google.golang.org/grpc && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc

# Change to /usr/src
WORKDIR /usr/src

# Copy BLUESPAWN source code into container
COPY ./ ./

# Compile Protobuf 
RUN protoc --go_out="$GOPATH/src" --go-grpc_out="$GOPATH/src" ./BLUESPAWN-common/bluespawnpb/bluespawn.proto

# Build and start rpc_server
RUN cd ./BLUESPAWN-server/rpc_server && \
    go build

ENTRYPOINT ["./BLUESPAWN-server/rpc_server/rpc_server"]
