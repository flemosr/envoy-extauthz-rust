// @generated
// [#protodoc-title: Attribute context]

// See :ref:`network filter configuration overview <config_network_filters_ext_authz>`
// and :ref:`HTTP filter configuration overview <config_http_filters_ext_authz>`.

/// An attribute is a piece of metadata that describes an activity on a network.
/// For example, the size of an HTTP request, or the status code of an HTTP response.
///
/// Each attribute has a type and a name, which is logically defined as a proto message field
/// of the ``AttributeContext``. The ``AttributeContext`` is a collection of individual attributes
/// supported by Envoy authorization system.
/// [#comment: The following items are left out of this proto
/// Request.Auth field for jwt tokens
/// Request.Api for api management
/// Origin peer that originated the request
/// Caching Protocol
/// request_context return values to inject back into the filter chain
/// peer.claims -- from X.509 extensions
/// Configuration
/// - field mask to send
/// - which return values from request_context are copied back
/// - which return values are copied into request_headers]
/// [#next-free-field: 13]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttributeContext {
    /// The source of a network activity, such as starting a TCP connection.
    /// In a multi hop network activity, the source represents the sender of the
    /// last hop.
    #[prost(message, optional, tag="1")]
    pub source: ::core::option::Option<attribute_context::Peer>,
    /// The destination of a network activity, such as accepting a TCP connection.
    /// In a multi hop network activity, the destination represents the receiver of
    /// the last hop.
    #[prost(message, optional, tag="2")]
    pub destination: ::core::option::Option<attribute_context::Peer>,
    /// Represents a network request, such as an HTTP request.
    #[prost(message, optional, tag="4")]
    pub request: ::core::option::Option<attribute_context::Request>,
    /// This is analogous to http_request.headers, however these contents will not be sent to the
    /// upstream server. Context_extensions provide an extension mechanism for sending additional
    /// information to the auth server without modifying the proto definition. It maps to the
    /// internal opaque context in the filter chain.
    #[prost(map="string, string", tag="10")]
    pub context_extensions: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
    /// Dynamic metadata associated with the request.
    #[prost(message, optional, tag="11")]
    pub metadata_context: ::core::option::Option<super::super::super::config::core::v3::Metadata>,
    /// TLS session details of the underlying connection.
    /// This is not populated by default and will be populated if ext_authz filter's
    /// :ref:`include_tls_session <config_http_filters_ext_authz>` is set to true.
    #[prost(message, optional, tag="12")]
    pub tls_session: ::core::option::Option<attribute_context::TlsSession>,
}
/// Nested message and enum types in `AttributeContext`.
pub mod attribute_context {
    /// This message defines attributes for a node that handles a network request.
    /// The node can be either a service or an application that sends, forwards,
    /// or receives the request. Service peers should fill in the ``service``,
    /// ``principal``, and ``labels`` as appropriate.
    /// [#next-free-field: 6]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Peer {
        /// The address of the peer, this is typically the IP address.
        /// It can also be UDS path, or others.
        #[prost(message, optional, tag="1")]
        pub address: ::core::option::Option<super::super::super::super::config::core::v3::Address>,
        /// The canonical service name of the peer.
        /// It should be set to :ref:`the HTTP x-envoy-downstream-service-cluster
        /// <config_http_conn_man_headers_downstream-service-cluster>`
        /// If a more trusted source of the service name is available through mTLS/secure naming, it
        /// should be used.
        #[prost(string, tag="2")]
        pub service: ::prost::alloc::string::String,
        /// The labels associated with the peer.
        /// These could be pod labels for Kubernetes or tags for VMs.
        /// The source of the labels could be an X.509 certificate or other configuration.
        #[prost(map="string, string", tag="3")]
        pub labels: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
        /// The authenticated identity of this peer.
        /// For example, the identity associated with the workload such as a service account.
        /// If an X.509 certificate is used to assert the identity this field should be sourced from
        /// ``URI Subject Alternative Names``, ``DNS Subject Alternate Names`` or ``Subject`` in that order.
        /// The primary identity should be the principal. The principal format is issuer specific.
        ///
        /// Examples:
        ///
        /// - SPIFFE format is ``spiffe://trust-domain/path``.
        /// - Google account format is ``<https://accounts.google.com/{userid}``.>
        #[prost(string, tag="4")]
        pub principal: ::prost::alloc::string::String,
        /// The X.509 certificate used to authenticate the identify of this peer.
        /// When present, the certificate contents are encoded in URL and PEM format.
        #[prost(string, tag="5")]
        pub certificate: ::prost::alloc::string::String,
    }
    /// Represents a network request, such as an HTTP request.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Request {
        /// The timestamp when the proxy receives the first byte of the request.
        #[prost(message, optional, tag="1")]
        pub time: ::core::option::Option<::prost_types::Timestamp>,
        /// Represents an HTTP request or an HTTP-like request.
        #[prost(message, optional, tag="2")]
        pub http: ::core::option::Option<HttpRequest>,
    }
    /// This message defines attributes for an HTTP request.
    /// HTTP/1.x, HTTP/2, gRPC are all considered as HTTP requests.
    /// [#next-free-field: 13]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct HttpRequest {
        /// The unique ID for a request, which can be propagated to downstream
        /// systems. The ID should have low probability of collision
        /// within a single day for a specific service.
        /// For HTTP requests, it should be X-Request-ID or equivalent.
        #[prost(string, tag="1")]
        pub id: ::prost::alloc::string::String,
        /// The HTTP request method, such as ``GET``, ``POST``.
        #[prost(string, tag="2")]
        pub method: ::prost::alloc::string::String,
        /// The HTTP request headers. If multiple headers share the same key, they
        /// must be merged according to the HTTP spec. All header keys must be
        /// lower-cased, because HTTP header keys are case-insensitive.
        #[prost(map="string, string", tag="3")]
        pub headers: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
        /// The request target, as it appears in the first line of the HTTP request. This includes
        /// the URL path and query-string. No decoding is performed.
        #[prost(string, tag="4")]
        pub path: ::prost::alloc::string::String,
        /// The HTTP request ``Host`` or ``:authority`` header value.
        #[prost(string, tag="5")]
        pub host: ::prost::alloc::string::String,
        /// The HTTP URL scheme, such as ``http`` and ``https``.
        #[prost(string, tag="6")]
        pub scheme: ::prost::alloc::string::String,
        /// This field is always empty, and exists for compatibility reasons. The HTTP URL query is
        /// included in ``path`` field.
        #[prost(string, tag="7")]
        pub query: ::prost::alloc::string::String,
        /// This field is always empty, and exists for compatibility reasons. The URL fragment is
        /// not submitted as part of HTTP requests; it is unknowable.
        #[prost(string, tag="8")]
        pub fragment: ::prost::alloc::string::String,
        /// The HTTP request size in bytes. If unknown, it must be -1.
        #[prost(int64, tag="9")]
        pub size: i64,
        /// The network protocol used with the request, such as "HTTP/1.0", "HTTP/1.1", or "HTTP/2".
        ///
        /// See :repo:`headers.h:ProtocolStrings <source/common/http/headers.h>` for a list of all
        /// possible values.
        #[prost(string, tag="10")]
        pub protocol: ::prost::alloc::string::String,
        /// The HTTP request body.
        #[prost(string, tag="11")]
        pub body: ::prost::alloc::string::String,
        /// The HTTP request body in bytes. This is used instead of
        /// :ref:`body <envoy_v3_api_field_service.auth.v3.AttributeContext.HttpRequest.body>` when
        /// :ref:`pack_as_bytes <envoy_v3_api_field_extensions.filters.http.ext_authz.v3.BufferSettings.pack_as_bytes>`
        /// is set to true.
        #[prost(bytes="vec", tag="12")]
        pub raw_body: ::prost::alloc::vec::Vec<u8>,
    }
    /// This message defines attributes for the underlying TLS session.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TlsSession {
        /// SNI used for TLS session.
        #[prost(string, tag="1")]
        pub sni: ::prost::alloc::string::String,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckRequest {
    /// The request attributes.
    #[prost(message, optional, tag="1")]
    pub attributes: ::core::option::Option<AttributeContext>,
}
/// HTTP attributes for a denied response.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeniedHttpResponse {
    /// This field allows the authorization service to send an HTTP response status code to the
    /// downstream client. If not set, Envoy sends ``403 Forbidden`` HTTP status code by default.
    #[prost(message, optional, tag="1")]
    pub status: ::core::option::Option<super::super::super::r#type::v3::HttpStatus>,
    /// This field allows the authorization service to send HTTP response headers
    /// to the downstream client. Note that the :ref:`append field in HeaderValueOption <envoy_v3_api_field_config.core.v3.HeaderValueOption.append>` defaults to
    /// false when used in this message.
    #[prost(message, repeated, tag="2")]
    pub headers: ::prost::alloc::vec::Vec<super::super::super::config::core::v3::HeaderValueOption>,
    /// This field allows the authorization service to send a response body data
    /// to the downstream client.
    #[prost(string, tag="3")]
    pub body: ::prost::alloc::string::String,
}
/// HTTP attributes for an OK response.
/// [#next-free-field: 9]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OkHttpResponse {
    /// HTTP entity headers in addition to the original request headers. This allows the authorization
    /// service to append, to add or to override headers from the original request before
    /// dispatching it to the upstream. Note that the :ref:`append field in HeaderValueOption <envoy_v3_api_field_config.core.v3.HeaderValueOption.append>` defaults to
    /// false when used in this message. By setting the ``append`` field to ``true``,
    /// the filter will append the correspondent header value to the matched request header.
    /// By leaving ``append`` as false, the filter will either add a new header, or override an existing
    /// one if there is a match.
    #[prost(message, repeated, tag="2")]
    pub headers: ::prost::alloc::vec::Vec<super::super::super::config::core::v3::HeaderValueOption>,
    /// HTTP entity headers to remove from the original request before dispatching
    /// it to the upstream. This allows the authorization service to act on auth
    /// related headers (like ``Authorization``), process them, and consume them.
    /// Under this model, the upstream will either receive the request (if it's
    /// authorized) or not receive it (if it's not), but will not see headers
    /// containing authorization credentials.
    ///
    /// Pseudo headers (such as ``:authority``, ``:method``, ``:path`` etc), as well as
    /// the header ``Host``, may not be removed as that would make the request
    /// malformed. If mentioned in ``headers_to_remove`` these special headers will
    /// be ignored.
    ///
    /// When using the HTTP service this must instead be set by the HTTP
    /// authorization service as a comma separated list like so:
    /// ``x-envoy-auth-headers-to-remove: one-auth-header, another-auth-header``.
    #[prost(string, repeated, tag="5")]
    pub headers_to_remove: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// This field has been deprecated in favor of :ref:`CheckResponse.dynamic_metadata
    /// <envoy_v3_api_field_service.auth.v3.CheckResponse.dynamic_metadata>`. Until it is removed,
    /// setting this field overrides :ref:`CheckResponse.dynamic_metadata
    /// <envoy_v3_api_field_service.auth.v3.CheckResponse.dynamic_metadata>`.
    #[deprecated]
    #[prost(message, optional, tag="3")]
    pub dynamic_metadata: ::core::option::Option<::prost_types::Struct>,
    /// This field allows the authorization service to send HTTP response headers
    /// to the downstream client on success. Note that the :ref:`append field in HeaderValueOption <envoy_v3_api_field_config.core.v3.HeaderValueOption.append>`
    /// defaults to false when used in this message.
    #[prost(message, repeated, tag="6")]
    pub response_headers_to_add: ::prost::alloc::vec::Vec<super::super::super::config::core::v3::HeaderValueOption>,
    /// This field allows the authorization service to set (and overwrite) query
    /// string parameters on the original request before it is sent upstream.
    #[prost(message, repeated, tag="7")]
    pub query_parameters_to_set: ::prost::alloc::vec::Vec<super::super::super::config::core::v3::QueryParameter>,
    /// This field allows the authorization service to specify which query parameters
    /// should be removed from the original request before it is sent upstream. Each
    /// element in this list is a case-sensitive query parameter name to be removed.
    #[prost(string, repeated, tag="8")]
    pub query_parameters_to_remove: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Intended for gRPC and Network Authorization servers ``only``.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckResponse {
    /// Status ``OK`` allows the request. Any other status indicates the request should be denied, and
    /// for HTTP filter, if not overridden by :ref:`denied HTTP response status <envoy_v3_api_field_service.auth.v3.DeniedHttpResponse.status>`
    /// Envoy sends ``403 Forbidden`` HTTP status code by default.
    #[prost(message, optional, tag="1")]
    pub status: ::core::option::Option<super::super::super::super::google::rpc::Status>,
    /// Optional response metadata that will be emitted as dynamic metadata to be consumed by the next
    /// filter. This metadata lives in a namespace specified by the canonical name of extension filter
    /// that requires it:
    ///
    /// - :ref:`envoy.filters.http.ext_authz <config_http_filters_ext_authz_dynamic_metadata>` for HTTP filter.
    /// - :ref:`envoy.filters.network.ext_authz <config_network_filters_ext_authz_dynamic_metadata>` for network filter.
    #[prost(message, optional, tag="4")]
    pub dynamic_metadata: ::core::option::Option<::prost_types::Struct>,
    /// An message that contains HTTP response attributes. This message is
    /// used when the authorization service needs to send custom responses to the
    /// downstream client or, to modify/add request headers being dispatched to the upstream.
    #[prost(oneof="check_response::HttpResponse", tags="2, 3")]
    pub http_response: ::core::option::Option<check_response::HttpResponse>,
}
/// Nested message and enum types in `CheckResponse`.
pub mod check_response {
    /// An message that contains HTTP response attributes. This message is
    /// used when the authorization service needs to send custom responses to the
    /// downstream client or, to modify/add request headers being dispatched to the upstream.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum HttpResponse {
        /// Supplies http attributes for a denied response.
        #[prost(message, tag="2")]
        DeniedResponse(super::DeniedHttpResponse),
        /// Supplies http attributes for an ok response.
        #[prost(message, tag="3")]
        OkResponse(super::OkHttpResponse),
    }
}
include!("envoy.service.auth.v3.tonic.rs");
// @@protoc_insertion_point(module)
