/// Schema is actually the `vitur-config` package from the Vitur repo.
/// It was becoming confusing having a crate and a module in this crate called vitur-config
/// that both do different things (probably indicating a naming problem).
/// Schema might make more sense but for now at least I'm not getting confused.
/// TODO: Consider moving vitur/vitur-config into cipherstash-client and call it schema
pub use schema::*;
