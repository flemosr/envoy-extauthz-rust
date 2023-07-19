use std::collections::HashMap;
use std::env;

use tonic::{transport::Server, Request, Response, Status};

mod pb;

use pb::envoy::config::core::v3::{
    header_value_option::HeaderAppendAction, HeaderValue, HeaderValueOption, QueryParameter,
};
use pb::envoy::r#type::v3::HttpStatus;
use pb::envoy::service::auth::v3::authorization_server::{Authorization, AuthorizationServer};
use pb::envoy::service::auth::v3::{
    check_response::HttpResponse, CheckRequest, CheckResponse, DeniedHttpResponse, OkHttpResponse,
};

use pb::google::rpc;

#[derive(Default)]
struct MyServer;

fn extract_inner_request_headers(
    request: Request<CheckRequest>,
) -> Option<HashMap<String, String>> {
    let inner = request.into_inner().attributes?.request?;
    Some(inner.http?.headers)
}

#[tonic::async_trait]
impl Authorization for MyServer {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        println!("{:?}", request);

        let denied_http_response = DeniedHttpResponse {
            status: Some(HttpStatus { code: 0 }),
            headers: Vec::new(),
            body: "REQUEST DENIED".to_string(),
        };

        let mut http_response = HttpResponse::DeniedResponse(denied_http_response);

        if let Some(headers) = extract_inner_request_headers(request) {
            println!("{:?}", headers);

            if let Some(authorization) = headers.get("authorization") {
                println!("{:?}", authorization);

                if authorization == "Bearer valid-token" {
                    #[allow(deprecated)]
                    let ok_http_response = OkHttpResponse {
                        headers: vec![HeaderValueOption {
                            header: Some(HeaderValue {
                                key: "header".to_string(),
                                value: "value".to_string(),
                                raw_value: Vec::new(),
                            }),
                            append: None, // Deprecated field
                            append_action: HeaderAppendAction::AddIfAbsent.into(),
                            keep_empty_value: false,
                        }],
                        headers_to_remove: Vec::new(),
                        dynamic_metadata: None, // Deprecated field
                        response_headers_to_add: Vec::new(),
                        query_parameters_to_remove: Vec::new(),
                        query_parameters_to_set: vec![QueryParameter {
                            key: "query_parameter".to_string(),
                            value: "query_value".to_string(),
                        }],
                    };

                    http_response = HttpResponse::OkResponse(ok_http_response);
                }
            }
        }

        let response_status = match http_response {
            HttpResponse::OkResponse(_) => rpc::Status {
                code: rpc::Code::Ok.into(),
                message: "request ok".to_string(),
                details: Vec::new(),
            },
            HttpResponse::DeniedResponse(_) => rpc::Status {
                code: rpc::Code::Unauthenticated.into(),
                message: "request denied".to_string(),
                details: Vec::new(),
            },
        };

        let response = CheckResponse {
            status: Some(response_status),
            dynamic_metadata: None,
            http_response: Some(http_response),
        };

        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_port = env::var("SERVER_PORT").expect("$SERVER_PORT not set");

    let addr = format!("0.0.0.0:{server_port}").parse().unwrap();
    let server = MyServer::default();

    println!("AuthorizationServer listening on {}", addr);

    Server::builder()
        .add_service(AuthorizationServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
