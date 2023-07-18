// @generated
/// HTTP status.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpStatus {
    /// Supplies HTTP response code.
    #[prost(enumeration = "StatusCode", tag = "1")]
    pub code: i32,
}
// [#protodoc-title: HTTP status codes]

/// HTTP response codes supported in Envoy.
/// For more details: <https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml>
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum StatusCode {
    /// Empty - This code not part of the HTTP status code specification, but it is needed for proto
    /// `enum` type.
    Empty = 0,
    Continue = 100,
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoritativeInformation = 203,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    MultiStatus = 207,
    AlreadyReported = 208,
    ImUsed = 226,
    MultipleChoices = 300,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    UseProxy = 305,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,
    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    PayloadTooLarge = 413,
    UriTooLong = 414,
    UnsupportedMediaType = 415,
    RangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    MisdirectedRequest = 421,
    UnprocessableEntity = 422,
    Locked = 423,
    FailedDependency = 424,
    UpgradeRequired = 426,
    PreconditionRequired = 428,
    TooManyRequests = 429,
    RequestHeaderFieldsTooLarge = 431,
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HttpVersionNotSupported = 505,
    VariantAlsoNegotiates = 506,
    InsufficientStorage = 507,
    LoopDetected = 508,
    NotExtended = 510,
    NetworkAuthenticationRequired = 511,
}
impl StatusCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            StatusCode::Empty => "Empty",
            StatusCode::Continue => "Continue",
            StatusCode::Ok => "OK",
            StatusCode::Created => "Created",
            StatusCode::Accepted => "Accepted",
            StatusCode::NonAuthoritativeInformation => "NonAuthoritativeInformation",
            StatusCode::NoContent => "NoContent",
            StatusCode::ResetContent => "ResetContent",
            StatusCode::PartialContent => "PartialContent",
            StatusCode::MultiStatus => "MultiStatus",
            StatusCode::AlreadyReported => "AlreadyReported",
            StatusCode::ImUsed => "IMUsed",
            StatusCode::MultipleChoices => "MultipleChoices",
            StatusCode::MovedPermanently => "MovedPermanently",
            StatusCode::Found => "Found",
            StatusCode::SeeOther => "SeeOther",
            StatusCode::NotModified => "NotModified",
            StatusCode::UseProxy => "UseProxy",
            StatusCode::TemporaryRedirect => "TemporaryRedirect",
            StatusCode::PermanentRedirect => "PermanentRedirect",
            StatusCode::BadRequest => "BadRequest",
            StatusCode::Unauthorized => "Unauthorized",
            StatusCode::PaymentRequired => "PaymentRequired",
            StatusCode::Forbidden => "Forbidden",
            StatusCode::NotFound => "NotFound",
            StatusCode::MethodNotAllowed => "MethodNotAllowed",
            StatusCode::NotAcceptable => "NotAcceptable",
            StatusCode::ProxyAuthenticationRequired => "ProxyAuthenticationRequired",
            StatusCode::RequestTimeout => "RequestTimeout",
            StatusCode::Conflict => "Conflict",
            StatusCode::Gone => "Gone",
            StatusCode::LengthRequired => "LengthRequired",
            StatusCode::PreconditionFailed => "PreconditionFailed",
            StatusCode::PayloadTooLarge => "PayloadTooLarge",
            StatusCode::UriTooLong => "URITooLong",
            StatusCode::UnsupportedMediaType => "UnsupportedMediaType",
            StatusCode::RangeNotSatisfiable => "RangeNotSatisfiable",
            StatusCode::ExpectationFailed => "ExpectationFailed",
            StatusCode::MisdirectedRequest => "MisdirectedRequest",
            StatusCode::UnprocessableEntity => "UnprocessableEntity",
            StatusCode::Locked => "Locked",
            StatusCode::FailedDependency => "FailedDependency",
            StatusCode::UpgradeRequired => "UpgradeRequired",
            StatusCode::PreconditionRequired => "PreconditionRequired",
            StatusCode::TooManyRequests => "TooManyRequests",
            StatusCode::RequestHeaderFieldsTooLarge => "RequestHeaderFieldsTooLarge",
            StatusCode::InternalServerError => "InternalServerError",
            StatusCode::NotImplemented => "NotImplemented",
            StatusCode::BadGateway => "BadGateway",
            StatusCode::ServiceUnavailable => "ServiceUnavailable",
            StatusCode::GatewayTimeout => "GatewayTimeout",
            StatusCode::HttpVersionNotSupported => "HTTPVersionNotSupported",
            StatusCode::VariantAlsoNegotiates => "VariantAlsoNegotiates",
            StatusCode::InsufficientStorage => "InsufficientStorage",
            StatusCode::LoopDetected => "LoopDetected",
            StatusCode::NotExtended => "NotExtended",
            StatusCode::NetworkAuthenticationRequired => "NetworkAuthenticationRequired",
        }
    }
}
// [#protodoc-title: Percent]

/// Identifies a percentage, in the range [0.0, 100.0].
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Percent {
    #[prost(double, tag = "1")]
    pub value: f64,
}
/// A fractional percentage is used in cases in which for performance reasons performing floating
/// point to integer conversions during randomness calculations is undesirable. The message includes
/// both a numerator and denominator that together determine the final fractional value.
///
/// * **Example**: 1/100 = 1%.
/// * **Example**: 3/10000 = 0.03%.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FractionalPercent {
    /// Specifies the numerator. Defaults to 0.
    #[prost(uint32, tag = "1")]
    pub numerator: u32,
    /// Specifies the denominator. If the denominator specified is less than the numerator, the final
    /// fractional percentage is capped at 1 (100%).
    #[prost(enumeration = "fractional_percent::DenominatorType", tag = "2")]
    pub denominator: i32,
}
/// Nested message and enum types in `FractionalPercent`.
pub mod fractional_percent {
    /// Fraction percentages support several fixed denominator values.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum DenominatorType {
        /// 100.
        ///
        /// **Example**: 1/100 = 1%.
        Hundred = 0,
        /// 10,000.
        ///
        /// **Example**: 1/10000 = 0.01%.
        TenThousand = 1,
        /// 1,000,000.
        ///
        /// **Example**: 1/1000000 = 0.0001%.
        Million = 2,
    }
    impl DenominatorType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                DenominatorType::Hundred => "HUNDRED",
                DenominatorType::TenThousand => "TEN_THOUSAND",
                DenominatorType::Million => "MILLION",
            }
        }
    }
}
// [#protodoc-title: Semantic version]

/// Envoy uses SemVer (<https://semver.org/>). Major/minor versions indicate
/// expected behaviors and APIs, the patch version field is used only
/// for security fixes and can be generally ignored.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SemanticVersion {
    #[prost(uint32, tag = "1")]
    pub major_number: u32,
    #[prost(uint32, tag = "2")]
    pub minor_number: u32,
    #[prost(uint32, tag = "3")]
    pub patch: u32,
}
// @@protoc_insertion_point(module)
