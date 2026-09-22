use crate::auth::{
    self, AuthCommand, AuthOptions, LoginArgs, ProfileCommand, ResolvedAuth, SavedProfileCommand,
};
use crate::gpg::{self, GpgCommand};
use crate::keygen::GenerateArgs;
use crate::operations::{ActivityCommand, RequestArgs, run_activity};
use crate::output::{ColorChoice, Ctx, ErrorMessage, MessageFormat, Shell, StdCtx};
use crate::resources::{ApiKeyCommand, PolicyCommand, PreparedResource, UserCommand};
use crate::secrets::{PreparedSecret, SecretCommand};
use crate::sessions::{self, SessionCommand};
use crate::ssh::{self, SshCommand};
use crate::wallets::{PreparedWalletCommand, SignCommand, WalletCommand};
use anyhow::Result;
use clap::{
    ArgAction, Args, CommandFactory, Parser, Subcommand, builder::FalseyValueParser,
    error::ErrorKind,
};
use serde::Serialize;
use std::env;
use std::ffi::OsString;
use std::fmt::Display;
use std::io::{self, Write};
use std::process::ExitCode;
use tracing::debug;

const LONG_ABOUT: &str = r#"CLI for Turnkey backed auth workflows.

Interactive behavior:
    By default, commands may prompt when stdin is a TTY. Use --non-interactive
    or set TK_NON_INTERACTIVE=true to disable prompts and fail fast instead.

Output format:
    --message-format human (default) prints human-readable text. Use
    --message-format json to emit machine-readable output instead: one JSON
    object per line (newline-delimited JSON), each with a "reason" field
    identifying the message, including errors. JSON mode implies
    --non-interactive, so commands never prompt and fail fast on missing input.

    Errors emit reason "command_error" (or "missing_required_input") plus a
    "code" classifying the failure, an optional numeric "httpStatus", optional
    "details" for recovery (such as the last observed activity identity), and
    a "message" carrying the full error chain. The "code" taxonomy is:
        missing_required_input  a required value was absent (non-interactive)
        usage_error             bad flags/args (argument parsing failed)
        invalid_input           semantic validation failed in the command
        unauthorized            HTTP 401/403
        not_found               HTTP 404, or a resource that resolved to empty
        api_error               other non-success HTTP status, or a failed,
                                rejected, or unexpected activity
        approval_required       the activity needs more approvals
        network_error           connect/timeout/DNS: request never reached the
                                server
        network_uncertain       transport failure where delivery cannot be
                                ruled out; reconcile before retrying a mutation
        submission_unknown      a mutation was sent but its outcome could not
                                be observed; inspect before resubmitting
        wait_timeout            activity wait ran out of time; resume with the
                                same ID
        session_expiring        the profile's credential ends within the
                                --warn-before window; request a new session
        command_error           fallback for everything else
    Exit codes: 0 success, 1 runtime error, 2 usage error."#;

const AFTER_HELP: &str = r#"API identity (login, whoami, request, activity, user, policy, api-key, wallet,
sign, gpg, ssh):
  Resolved from exactly one source: the TURNKEY_ORGANIZATION_ID,
  TURNKEY_API_PUBLIC_KEY, TURNKEY_API_PRIVATE_KEY environment bundle; else the
  profile named by --profile or TK_PROFILE (an explicit profile always wins);
  else the registry's active profile.
  The profile registry lives at ~/.config/turnkey/tk.config.toml.
  TURNKEY_API_BASE_URL overrides the API endpoint.

SSH agent:
  tk ssh agent start
  export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock

Skills:
  Download https://github.com/tkhq/tk/tree/main/skills into your agent's skills
  directory and start from its SKILL.md.
"#;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "CLI for Turnkey backed auth workflows",
    long_about = LONG_ABOUT,
    after_help = AFTER_HELP
)]
pub struct Cli {
    #[command(flatten)]
    auth: AuthOptions,

    #[command(flatten)]
    output: OutputOptions,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Args)]
struct OutputOptions {
    /// Disable interactive prompts and fail fast when required values are missing.
    ///
    /// Via the environment, an empty or falsey value (false, 0, no, off) leaves
    /// prompts enabled and any other value disables them.
    #[arg(
        long,
        global = true,
        env = "TK_NON_INTERACTIVE",
        action = ArgAction::SetTrue,
        value_parser = FalseyValueParser::new()
    )]
    non_interactive: bool,

    /// Format user-facing output.
    #[arg(long, global = true, value_enum, default_value_t = MessageFormat::Human)]
    message_format: MessageFormat,

    /// Control ANSI color in user-facing output.
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

impl Cli {
    pub async fn run() -> ExitCode {
        let Cli {
            auth,
            output,
            command,
        } = match Cli::try_parse() {
            Ok(args) => args,
            Err(error) => return handle_parse_error(error),
        };
        debug!(
            command = command.name(),
            non_interactive = output.non_interactive,
            message_format = ?output.message_format,
            color = ?output.color,
            "dispatching"
        );
        match command {
            Commands::Profile {
                command:
                    ProfileCommand::Saved(SavedProfileCommand::Set {
                        api_key_file: None, ..
                    }),
            } if auth.organization_id().is_none() && auth.api_base_url().is_none() => {
                handle_parse_error(Cli::command().error(
                    ErrorKind::MissingRequiredArgument,
                    "profile set requires --organization-id, --api-base-url, or --api-key-file",
                ))
            }
            Commands::Profile {
                command: ProfileCommand::Create(create),
            } => {
                let Some(organization_id) = auth.organization_id() else {
                    return handle_parse_error(Cli::command().error(
                        ErrorKind::MissingRequiredArgument,
                        "profile create requires --organization-id",
                    ));
                };
                let api_base_url = auth::endpoint_override(&auth).map(Option::unwrap_or_default);
                let mut ctx = ready(output).await;
                let result = match api_base_url {
                    Ok(api_base_url) => {
                        auth::create_profile(create, organization_id, api_base_url).await
                    }
                    Err(error) => Err(error),
                };
                emit(&mut ctx, result)
            }
            Commands::Profile {
                command: ProfileCommand::Saved(command),
            } => {
                let mut ctx = ready(output).await;
                emit(&mut ctx, auth::run_profile(command, &auth).await)
            }
            Commands::Operation(operation) => run_operation(&auth, output, operation).await,
        }
    }
}

async fn ready(output: OutputOptions) -> StdCtx {
    let shell = Shell::standard(output.message_format, output.color);
    let ctx = Ctx::new(shell, output.non_interactive);
    auth::sweep_state().await;
    ctx
}

async fn run_operation(
    options: &AuthOptions,
    output: OutputOptions,
    operation: Operation,
) -> ExitCode {
    let mut ctx = ready(output).await;
    let result = match operation {
        Operation::Ssh { command } => return emit(&mut ctx, ssh::run(command, options).await),
        Operation::ApiKey {
            command: ApiKeyCommands::Generate(generate),
        } => return emit(&mut ctx, generate.run().await),
        Operation::Gpg { command } => return emit(&mut ctx, gpg::run(command, options).await),
        Operation::Request(request) => {
            run_prepared(request.prepare(), options, async |prepared, auth| {
                prepared.run(&auth).await
            })
            .await
        }
        Operation::Activity { command } => {
            run_prepared(Ok(command), options, async |command, auth| {
                run_activity(command, &auth).await
            })
            .await
        }
        Operation::User { command } => {
            run_prepared(command.prepare(), options, PreparedResource::run).await
        }
        Operation::Policy { command } => {
            run_prepared(command.prepare(), options, PreparedResource::run).await
        }
        Operation::ApiKey {
            command: ApiKeyCommands::Remote(command),
        } => run_prepared(command.prepare(), options, PreparedResource::run).await,
        Operation::Wallet { command } => {
            run_prepared(command.prepare(), options, PreparedWalletCommand::run).await
        }
        Operation::Sign { command } => {
            run_prepared(command.prepare(), options, PreparedWalletCommand::run).await
        }
        Operation::Secret { command } => {
            let result = run_prepared(
                command.prepare(ctx.is_non_interactive()),
                options,
                PreparedSecret::run,
            )
            .await;
            return emit(&mut ctx, result);
        }
        Operation::Session { command } => sessions::run(command, options).await,
        Operation::Login(login) => auth::run_auth(AuthCommand::Login(login), options).await,
        Operation::Whoami => auth::run_auth(AuthCommand::Whoami, options).await,
        Operation::Auth { command } => auth::run_auth(command, options).await,
    };
    emit(&mut ctx, result)
}

async fn run_prepared<P, M>(
    prepared: Result<P>,
    options: &AuthOptions,
    run: impl AsyncFnOnce(P, ResolvedAuth) -> Result<M>,
) -> Result<M> {
    let prepared = prepared?;
    let auth = auth::resolve(options).await?;
    run(prepared, auth).await
}

fn emit<M: Serialize + Display>(ctx: &mut StdCtx, result: Result<M>) -> ExitCode {
    match result {
        Ok(message) => match ctx.shell().emit(&message) {
            Ok(()) => ExitCode::SUCCESS,
            Err(emit_error) => {
                let mut stderr = io::stderr();
                let _ = writeln!(stderr, "error: failed to write CLI output: {emit_error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            debug!(?error, "command failed");

            let shell = ctx.shell();
            let emit_result = if shell.message_format().is_json() {
                shell.emit(&ErrorMessage::from_error(&error))
            } else {
                shell.human().error(&error)
            };
            if let Err(emit_error) = emit_result {
                let mut stderr = io::stderr();
                let _ = writeln!(stderr, "error: failed to write CLI error: {emit_error}");
            }
            ExitCode::FAILURE
        }
    }
}

const USAGE_ERROR_EXIT_CODE: u8 = 2;

fn handle_parse_error(error: clap::Error) -> ExitCode {
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => error.exit(),
        _ if args_request_json_output(env::args_os()) => {
            let message = error.render().to_string().trim_end().to_string();
            let error_message = ErrorMessage::usage_error(message);

            // ErrorMessage holds only strings and an enum, so serializing it cannot fail.
            #[allow(clippy::expect_used)]
            let msg =
                serde_json::to_string(&error_message).expect("usage error message serializes");

            let _ = writeln!(io::stdout(), "{msg}");
            ExitCode::from(USAGE_ERROR_EXIT_CODE)
        }
        _ => error.exit(),
    }
}

fn args_request_json_output(args: impl IntoIterator<Item = OsString>) -> bool {
    const FLAG: &str = "--message-format";
    const JSON_FLAG: &str = "--message-format=json";

    let args: Vec<_> = args.into_iter().collect();

    args.iter().any(|arg| arg == JSON_FLAG)
        || args
            .windows(2)
            .any(|pair| pair[0] == FLAG && pair[1] == "json")
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(flatten)]
    Operation(Operation),
    /// Manage named API identities.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
}

#[derive(Debug, Subcommand)]
enum Operation {
    /// Inspect, approve, reject, and wait for activities.
    Activity {
        #[command(subcommand)]
        command: ActivityCommand,
    },
    /// SSH related commands.
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
    },
    /// Send an arbitrary signed API request.
    Request(RequestArgs),
    /// Manage users and user tags.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Manage policies and inspect evaluations.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Manage registered API credentials.
    ApiKey {
        #[command(subcommand)]
        command: ApiKeyCommands,
    },
    /// Manage wallets and accounts.
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },
    /// Sign payloads and serialized transactions.
    Sign {
        #[command(subcommand)]
        command: SignCommand,
    },
    /// List, import, and export Secrets.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Short-lived credentials for agent profiles.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Create PGP keys as wallet accounts, register them, export them, and sign with them.
    Gpg {
        #[command(subcommand)]
        command: GpgCommand,
    },
    /// Verify a saved profile with Turnkey and select it.
    Login(LoginArgs),
    /// Verify the selected identity remotely.
    Whoami,
    /// Manage API authentication.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ApiKeyCommands {
    /// Generate a protected local credential file without registration.
    Generate(GenerateArgs),
    #[command(flatten)]
    Remote(ApiKeyCommand),
}

impl Commands {
    fn name(&self) -> &'static str {
        match self {
            Commands::Operation(operation) => operation.name(),
            Commands::Profile { .. } => "profile",
        }
    }
}

impl Operation {
    fn name(&self) -> &'static str {
        match self {
            Operation::Activity { .. } => "activity",
            Operation::Ssh { .. } => "ssh",
            Operation::Request(_) => "request",
            Operation::User { .. } => "user",
            Operation::Policy { .. } => "policy",
            Operation::ApiKey { .. } => "api-key",
            Operation::Wallet { .. } => "wallet",
            Operation::Sign { .. } => "sign",
            Operation::Secret { .. } => "secret",
            Operation::Session { .. } => "session",
            Operation::Gpg { .. } => "gpg",
            Operation::Login(_) => "login",
            Operation::Whoami => "whoami",
            Operation::Auth { .. } => "auth",
        }
    }
}

// Checks that help documents every error code.
#[cfg(test)]
#[allow(clippy::disallowed_types)]
mod tests {
    use super::*;
    use crate::errors::ErrorCode;
    use std::collections::BTreeSet;
    use strum::IntoEnumIterator;

    #[test]
    fn help_documents_every_error_code() {
        let declared: BTreeSet<String> = ErrorCode::iter()
            .map(|code| {
                serde_json::to_value(code)
                    .expect("every error code must serialize")
                    .as_str()
                    .expect("every error code must serialize as a JSON string")
                    .to_string()
            })
            .collect();
        let documented: BTreeSet<String> = LONG_ABOUT
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("        ")?;
                if rest.starts_with(' ') {
                    return None;
                }
                let (token, _) = rest.split_once("  ")?;
                token
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_')
                    .then(|| token.to_string())
            })
            .collect();
        assert_eq!(documented, declared);
    }

    #[test]
    fn json_output_request_is_detected_in_both_spellings() {
        for args in [
            vec!["tk", "--message-format=json", "config", "list"],
            vec!["tk", "config", "list", "--message-format", "json"],
        ] {
            assert!(args_request_json_output(
                args.into_iter().map(OsString::from)
            ));
        }
        assert!(!args_request_json_output(
            ["tk", "config", "list"].into_iter().map(OsString::from)
        ));
    }
}
