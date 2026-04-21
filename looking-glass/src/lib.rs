// Library target exposing modules for use by lg-server, lg-cli, lg-http.
// During the transition, the binary (main.rs) still works as before.

pub mod command;
pub mod grammar;
pub mod config;
pub mod identity;
pub mod netbox;
pub mod oidc;
pub mod participants;
pub mod policy;
pub mod ratelimit;
pub mod structured;
pub mod format;
pub mod ixf;
pub mod service;

pub mod backend;
pub mod bgp;
pub mod frontend;
