mod auth;
pub(crate) mod helpers;
mod secrets;
mod setup;
mod vault;

pub use auth::{cmd_lock, get_data_dir, get_passphrase, load_config, open_db};
pub use secrets::{
    cmd_add, cmd_export, cmd_get, cmd_health, cmd_import, cmd_list, cmd_remove, cmd_run, cmd_scan,
    cmd_search, cmd_update, cmd_verify, AddArgs, UpdateArgs,
};
pub use setup::{cmd_serve, cmd_setup};
pub use vault::{cmd_backup, cmd_init, cmd_passwd, cmd_restore};
