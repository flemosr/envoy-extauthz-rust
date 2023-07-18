pub mod envoy {

    mod r#type {
        pub mod v3 {
            include!("./envoy/type/v3/envoy.type.v3.rs");
        }
    }

    mod config {
        pub mod core {
            pub mod v3 {
                include!("./envoy/config/core/v3/envoy.config.core.v3.rs");
            }
        }
    }

    pub mod service {
        pub mod auth {
            pub mod v3 {
                include!("./envoy/service/auth/v3/envoy.service.auth.v3.rs");
            }
        }
    }
}

mod google {
    pub mod rpc {
        include!("./google/rpc/google.rpc.rs");
    }
}

mod xds {
    pub mod core {
        pub mod v3 {
            include!("./xds/core/v3/xds.core.v3.rs");
        }
    }
}
