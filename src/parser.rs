pub(crate) mod header;
pub(crate) mod name;
pub mod packet;
pub(crate) mod question;
pub mod record;
pub mod sigin;
pub mod varint;

pub use name::{NameCompression, put_name};
