# Envoy's ExtAuthZ with a Rust Service

## Compiling protos to Rust

```console
$ cd ./proto

$ dev protoc -I=./ ./$PROTO_PATH/*.proto \
    --prost_out=./target/$PROTO_PATH \
    --tonic_out=./target/$PROTO_PATH
```

```bash
# Our main target
$ PROTO_PATH=envoy/service/auth/v3

$ PROTO_PATH=envoy/config/core/v3

$ PROTO_PATH=envoy/type/v3

$ PROTO_PATH=xds/core/v3

$ PROTO_PATH=google/rpc
```