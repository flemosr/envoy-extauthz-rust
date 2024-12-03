# Envoy External Authorization Server (ext_authz) in Rust

This is an example showing how to implement an [Envoy External Authorization]
gRPC Server written in Rust, using the [envoy-types] crate. If you are working
on a more complex implementation including rate-limiting, consider checking out
the [envoy-extauthz-rust-rate-limit] repository.

Here, we create an `envoy` service mapped to a localhost port, connected through
internal docker networks to an `extauthz` service, and to a `nginx` service that
serves plain text.

When `envoy` receives a request, it checks its validity through the `extauthz`
service. If the request is considered valid, it is sent to `nginx`,
with any appended headers and query parameters that the `extauthz` service
added to it. If not, `envoy` sends the `extauthz` denied response back to the
client.

[Envoy External Authorization]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter
[envoy-types]: https://crates.io/crates/envoy-types
[envoy-extauthz-rust-rate-limit]: https://github.com/flemosr/envoy-extauthz-rust-rate-limit

## Run the Example

To run this example, you must have `Docker` installed (with `docker compose`). 
Instructions can be found [here](https://docs.docker.com/get-docker/).

### Setup Expected Environment Variables

The `docker-compose` file expects a few `env` variables that need to be provided
in order to run its services. An example configuration follows:

```env
DOCKER_REGISTRY=playground.local

# If set to any value, the 'extauthz' server will be compiled in 'release' mode
RELEASE_BUILD=""

EXT_AUTHZ_PORT=50051

NGINX_SERVER_PORT=8080

NGINX_SERVER_NAME=localhost

ENVOY_SERVER_PORT=10000

ENVOY_ADMIN_PORT=9901

# Port on localhost where the requests should be directed to
ENVOY_EXTERNAL_PORT=3000
```

Create a `.env` file in the repo directory with the values above.

### Run the services

Build and run `envoy` and the services it depends on.

```console
$ docker compose up -d --build envoy
```

Check with `docker ps` if the three containers are running, and if the port
10000 of the envoy container is mapped to the localhost port 3000, as expected
from the example environment configuration.

### Send Requests to Envoy

Requests containing an "`Authorization`" header with value "`Bearer valid-token`"
will be considered valid and, therefore, will reach the `nginx` service. Other
requests will be blocked.

Making a valid request:

```console
$ curl http://localhost:3000 -H "Authorization: Bearer valid-token"

DATA FROM NGINX SERVER
```

Making an invalid request:

```console
$ curl http://localhost:3000

FORBIDDEN
```

### Check Nginx Logs

Check if the headers and query parameters added by the `extauthz` service indeed
reached the `nginx` service.

```console
$ docker compose logs nginx
```

The valid request log should be similar to:

```log
...
extauthz-rust.nginx  | 192.168.128.3 - - [01/Dec/2024:14:32:29 +0000] "GET /?extauthz-query-param=extauthz-query-value HTTP/1.1" 200 22 "-" "curl/8.7.1" "192.168.65.1" "extauthz-value"
```

## License

This project is licensed under the [MIT License](LICENSE).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, shall be licensed as MIT, without any
additional terms or conditions.