mod add;
mod auth;
mod export;
mod get_remove;
pub(crate) mod helpers;
mod import;
mod prompts;
mod query;
mod run;
mod scan;
mod secrets;
mod setup;
mod sync;
mod update;
mod vault;

pub use add::{cmd_add, AddArgs};
pub use export::cmd_export;
pub use get_remove::{cmd_get, cmd_remove};
pub use import::{cmd_import, ImportArgs};
pub use query::{cmd_health, cmd_list, cmd_search, cmd_verify};
pub use run::cmd_run;
pub use scan::{cmd_scan, ScanArgs};
pub use update::{cmd_update, UpdateArgs};

pub use auth::{cmd_lock, cmd_unlock, get_data_dir, get_passphrase, load_config, open_db};
pub use setup::{cmd_serve, cmd_setup};
pub use sync::cmd_sync;
pub use vault::{cmd_backup, cmd_init, cmd_passwd, cmd_restore, cmd_upgrade};
