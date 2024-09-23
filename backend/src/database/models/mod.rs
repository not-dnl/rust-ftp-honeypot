//! Contains the models that represent the database entries
//!
//! Also contains the [sea_orm] implementation and intrinsic models
//!
//! [sea_orm]: https://www.sea-ql.org/SeaORM/docs/introduction/orm/

pub mod prelude;

pub mod attacker;
pub mod attacker_to_credentials;
pub mod credentials;
pub mod uploaded_files;
