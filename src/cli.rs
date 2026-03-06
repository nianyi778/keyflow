use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "keyflow",
    about = "AI-Native Secret Manager - Let AI coding assistants discover and use your API keys",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize KeyFlow vault with a master passphrase
    Init {
        /// Set passphrase non-interactively
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Change master passphrase (re-encrypts all secrets)
    Passwd {
        /// Current passphrase (or use KEYFLOW_PASSPHRASE env)
        #[arg(long)]
        old: Option<String>,
        /// New passphrase
        #[arg(long)]
        new: Option<String>,
    },

    /// Backup vault to an encrypted file
    Backup {
        /// Output path (default: ~/keyflow-backup-<date>.json.enc)
        #[arg(long, short)]
        output: Option<String>,
    },

    /// Restore vault from a backup file
    Restore {
        /// Path to backup file
        file: String,
        /// Passphrase used when backup was created
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Add a secret: `kf add MY_KEY "value"` or `kf add` for interactive
    Add {
        /// Environment variable name (e.g. GOOGLE_CLIENT_ID)
        env_var: Option<String>,
        /// Secret value (use "-" to read from stdin, omit for interactive prompt)
        value: Option<String>,
        /// Provider (auto-detected from env var name if omitted)
        #[arg(short, long)]
        provider: Option<String>,
        /// Project tags (comma-separated)
        #[arg(short = 'P', long)]
        projects: Option<String>,
        /// Key group name
        #[arg(short, long)]
        group: Option<String>,
        /// Description
        #[arg(short, long)]
        desc: Option<String>,
        /// Expiry date (YYYY-MM-DD)
        #[arg(short, long)]
        expires: Option<String>,
        /// Read value from clipboard (macOS: pbpaste)
        #[arg(long)]
        paste: bool,
    },

    /// List all secrets
    List {
        /// Filter by provider
        #[arg(long)]
        provider: Option<String>,
        /// Filter by project tag
        #[arg(long)]
        project: Option<String>,
        /// Filter by key group
        #[arg(long)]
        group: Option<String>,
        /// Show only expiring/expired keys
        #[arg(long)]
        expiring: bool,
        /// Show inactive keys
        #[arg(long)]
        inactive: bool,
    },

    /// Get a secret value: `kf get` to select, or `kf get <name>`
    Get {
        /// Secret name (omit to select interactively)
        name: Option<String>,
        /// Output only the value (no decoration)
        #[arg(long)]
        raw: bool,
        /// Copy value to clipboard
        #[arg(short, long)]
        copy: bool,
    },

    /// Remove a secret: `kf remove` to select, or `kf remove <name>`
    Remove {
        /// Secret name (omit to select interactively)
        name: Option<String>,
        /// Skip confirmation
        #[arg(long, short)]
        force: bool,
    },

    /// Update a secret: `kf update` to select, or `kf update <name>`
    Update {
        /// Secret name (omit to select interactively)
        name: Option<String>,
        /// New value
        #[arg(long)]
        value: Option<String>,
        /// New provider
        #[arg(long)]
        provider: Option<String>,
        /// New description
        #[arg(long)]
        desc: Option<String>,
        /// New comma-separated scopes
        #[arg(long)]
        scopes: Option<String>,
        /// New comma-separated project tags
        #[arg(long)]
        projects: Option<String>,
        /// New management URL
        #[arg(long)]
        url: Option<String>,
        /// New expiry date (YYYY-MM-DD)
        #[arg(long)]
        expires: Option<String>,
        /// Toggle active/inactive
        #[arg(long)]
        active: Option<bool>,
        /// Set key group
        #[arg(long)]
        group: Option<String>,
    },

    /// Run a command with secrets injected: `kf run -- npm start`
    Run {
        /// Project filter (auto-detected from package.json/Cargo.toml if omitted)
        #[arg(short, long)]
        project: Option<String>,
        /// Group filter
        #[arg(short, long)]
        group: Option<String>,
        /// Inject all secrets (skip project auto-detection)
        #[arg(short, long)]
        all: bool,
        /// The command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Import secrets from a .env file
    Import {
        /// Path to .env file
        file: String,
        /// Provider to assign to all imported keys
        #[arg(long)]
        provider: Option<String>,
        /// Project tag to assign
        #[arg(long)]
        project: Option<String>,
        /// Conflict strategy: skip (default), overwrite, rename
        #[arg(long, default_value = "skip")]
        on_conflict: String,
    },

    /// Export secrets as .env format
    Export {
        /// Filter by project
        #[arg(long)]
        project: Option<String>,
        /// Filter by group
        #[arg(long)]
        group: Option<String>,
        /// Output file (default: stdout)
        #[arg(long, short)]
        output: Option<String>,
    },

    /// Check health status of all secrets
    Health,

    /// Search secrets by keyword: `kf search` to type interactively
    Search {
        /// Search query (omit for interactive prompt)
        query: Option<String>,
    },

    /// Manage key groups (bundles of related secrets)
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },

    /// Use a predefined template to create a bundle of secrets
    Template {
        #[command(subcommand)]
        action: TemplateAction,
    },

    /// Clear passphrase session (require re-auth on next command)
    Lock,

    /// Start MCP server (for AI coding assistants)
    Serve,

    /// Generate shell completions
    Completions {
        /// Shell type
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Launch interactive TUI
    Ui,

    /// Open local web dashboard
    #[command(alias = "dashboard")]
    Web {
        /// Port to listen on
        #[arg(long, default_value = "9876")]
        port: u16,
    },
}

#[derive(Subcommand)]
pub enum GroupAction {
    /// List all groups
    List,
    /// Show secrets in a group
    Show {
        /// Group name
        name: String,
    },
    /// Export a group as .env
    Export {
        /// Group name
        name: String,
        /// Output file (default: stdout)
        #[arg(long, short)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TemplateAction {
    /// List available templates
    List,
    /// Create secrets from a template
    Use {
        /// Template name (e.g., google-oauth, stripe, supabase)
        name: String,
        /// Comma-separated project tags to assign
        #[arg(long)]
        projects: Option<String>,
        /// Expiry date (YYYY-MM-DD)
        #[arg(long)]
        expires: Option<String>,
        /// Custom prefix for env var names (e.g., MYAPP_)
        #[arg(long)]
        prefix: Option<String>,
    },
}
