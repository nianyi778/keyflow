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

    /// Add a new secret (interactive)
    Add {
        /// Non-interactive mode: secret name
        #[arg(long)]
        name: Option<String>,
        /// Non-interactive: environment variable name
        #[arg(long)]
        env_var: Option<String>,
        /// Non-interactive: secret value
        #[arg(long)]
        value: Option<String>,
        /// Provider (e.g., google, github, cloudflare)
        #[arg(long)]
        provider: Option<String>,
        /// Description
        #[arg(long)]
        desc: Option<String>,
        /// Comma-separated scopes
        #[arg(long)]
        scopes: Option<String>,
        /// Comma-separated project tags
        #[arg(long)]
        projects: Option<String>,
        /// URL to manage/renew the key
        #[arg(long)]
        url: Option<String>,
        /// Expiry date (YYYY-MM-DD)
        #[arg(long)]
        expires: Option<String>,
        /// Key group name (bundle related keys)
        #[arg(long)]
        group: Option<String>,
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

    /// Get a secret value by name
    Get {
        /// Secret name
        name: String,
        /// Output only the value (no decoration)
        #[arg(long)]
        raw: bool,
    },

    /// Remove a secret
    Remove {
        /// Secret name
        name: String,
        /// Skip confirmation
        #[arg(long, short)]
        force: bool,
    },

    /// Update a secret's value or metadata
    Update {
        /// Secret name
        name: String,
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

    /// Run a command with secrets injected as environment variables
    Run {
        /// Only inject secrets tagged with this project
        #[arg(long)]
        project: Option<String>,
        /// Only inject secrets from this group
        #[arg(long)]
        group: Option<String>,
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

    /// Search secrets by keyword
    Search {
        /// Search query
        query: String,
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

    /// Start MCP server (for AI coding assistants)
    Serve,

    /// Generate shell completions
    Completions {
        /// Shell type
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Start local web dashboard
    Dashboard {
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
