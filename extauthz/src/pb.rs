pub mod envoy {

    pub mod r#type {
        pub mod v3 {
            include!("./generated/envoy.r#type.v3.rs");
        }
    }

    pub mod config {
        pub mod core {
            pub mod v3 {
                include!("./generated/envoy.config.core.v3.rs");
            }
        }
    }

    pub mod service {
        pub mod auth {
            pub mod v3 {
                include!("./generated/envoy.service.auth.v3.rs");
            }
        }
    }
}

pub mod google {
    pub mod rpc {
        include!("./generated/google.rpc.rs");
    }
}

pub mod udpa {
    pub mod annotations {
        pub mod v3 {
            include!("./generated/udpa.annotations.rs");
        }
    }
}

pub mod validate {
    include!("./generated/validate.rs");
}

pub mod xds {
    pub mod annotations {
        pub mod v3 {
            include!("./generated/xds.annotations.v3.rs");
        }
    }
    pub mod core {
        pub mod v3 {
            include!("./generated/xds.core.v3.rs");
        }
    }
}
