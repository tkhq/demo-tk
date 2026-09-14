use crate::{
    auth::{ResolvedAuth, build_turnkey_client},
    errors::{Malformed, MissingResource},
    operations::{OperationOutput, submit_activity},
    resources::BodyArgs,
};
use anyhow::Result;
use clap::Subcommand;
use serde_json::to_value;
use turnkey_client::generated::{
    GetPrivateKeyRequest, GetPrivateKeysRequest,
    immutable::activity::v1::{CreatePrivateKeysIntentV2, DeletePrivateKeysIntent},
};
use uuid::Uuid;

#[derive(Debug, Subcommand)]
pub enum PrivateKeyCommand {
    List,
    Get {
        id: Uuid,
    },
    /// Create private keys from a JSON body with a `privateKeys` list.
    Create(BodyArgs),
    /// Delete the private keys named in `privateKeyIds`; `deleteWithoutExport` skips the export check.
    Delete(BodyArgs),
}

pub enum PreparedPrivateKeyCommand {
    Query(PrivateKeyQuery),
    Mutation(PrivateKeyMutation),
}

pub enum PrivateKeyQuery {
    List,
    Get(Uuid),
}

pub enum PrivateKeyMutation {
    Create(CreatePrivateKeysIntentV2),
    Delete {
        private_key_ids: Vec<Uuid>,
        delete_without_export: Option<bool>,
    },
}

impl PrivateKeyCommand {
    pub fn prepare(self) -> Result<PreparedPrivateKeyCommand> {
        Ok(match self {
            Self::List => PreparedPrivateKeyCommand::Query(PrivateKeyQuery::List),
            Self::Get { id } => PreparedPrivateKeyCommand::Query(PrivateKeyQuery::Get(id)),
            Self::Create(input) => {
                PreparedPrivateKeyCommand::Mutation(PrivateKeyMutation::Create(input.parse()?))
            }
            Self::Delete(input) => {
                let DeletePrivateKeysIntent {
                    private_key_ids,
                    delete_without_export,
                } = input.parse()?;
                let private_key_ids = private_key_ids
                    .iter()
                    .map(|id| Uuid::parse_str(id))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| Malformed::new("privateKeyIds must be UUIDs", error))?;
                PreparedPrivateKeyCommand::Mutation(PrivateKeyMutation::Delete {
                    private_key_ids,
                    delete_without_export,
                })
            }
        })
    }
}

impl PreparedPrivateKeyCommand {
    pub async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        match self {
            Self::Query(query) => query.run(auth).await,
            Self::Mutation(mutation) => mutation.run(auth).await,
        }
    }
}

impl PrivateKeyMutation {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let (command, endpoint, kind, params) = match self {
            Self::Create(p) => (
                "private-key.create",
                "create_private_keys",
                "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
                to_value(p)?,
            ),
            Self::Delete {
                private_key_ids,
                delete_without_export,
            } => (
                "private-key.delete",
                "delete_private_keys",
                "ACTIVITY_TYPE_DELETE_PRIVATE_KEYS",
                to_value(DeletePrivateKeysIntent {
                    private_key_ids: private_key_ids.iter().map(Uuid::to_string).collect(),
                    delete_without_export,
                })?,
            ),
        };
        submit_activity(&auth, command, endpoint, kind, &params).await
    }
}

impl PrivateKeyQuery {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
        let organization_id = auth.org_id.to_string();
        match self {
            Self::List => {
                let data = client
                    .get_private_keys(GetPrivateKeysRequest { organization_id })
                    .await?;
                Ok(OperationOutput::result("private-key.list", to_value(data)?))
            }
            Self::Get(id) => {
                let data = client
                    .get_private_key(GetPrivateKeyRequest {
                        organization_id,
                        private_key_id: id.to_string(),
                    })
                    .await?;
                if data.private_key.is_none() {
                    return Err(MissingResource::new("private key", id.to_string()).into());
                }
                Ok(OperationOutput::result("private-key.get", to_value(data)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use clap::error::ErrorKind;

    #[derive(Debug, Parser)]
    struct PrivateKeyParser {
        #[command(subcommand)]
        command: PrivateKeyCommand,
    }

    #[test]
    fn conflicting_or_missing_inputs_fail_during_parsing() {
        assert_eq!(
            PrivateKeyParser::try_parse_from(["private-key", "create"])
                .unwrap_err()
                .kind(),
            ErrorKind::MissingRequiredArgument
        );
        let both = "private-key create --input-json {} --input-file x".split(' ');
        assert_eq!(
            PrivateKeyParser::try_parse_from(both).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn private_key_uuid_is_checked_before_authentication() {
        assert_eq!(
            PrivateKeyParser::try_parse_from(["private-key", "get", "not-an-id"])
                .unwrap_err()
                .kind(),
            ErrorKind::ValueValidation
        );
        let parsed = PrivateKeyParser::try_parse_from([
            "private-key",
            "delete",
            "--input-json",
            r#"{"privateKeyIds":["bad"]}"#,
        ])
        .unwrap();
        let error = parsed
            .command
            .prepare()
            .err()
            .expect("prepare should have failed");
        let malformed = error
            .downcast_ref::<Malformed>()
            .expect("a malformed private key id is a Malformed error");
        assert_eq!(malformed.to_string(), "privateKeyIds must be UUIDs");
    }

    #[test]
    fn delete_preserves_typed_ids_and_export_flag() {
        let id = Uuid::new_v4();
        let parsed = PrivateKeyParser::try_parse_from([
            "private-key",
            "delete",
            "--input-json",
            &format!(r#"{{"privateKeyIds":["{id}"],"deleteWithoutExport":true}}"#),
        ])
        .unwrap();
        let PreparedPrivateKeyCommand::Mutation(PrivateKeyMutation::Delete {
            private_key_ids,
            delete_without_export,
        }) = parsed.command.prepare().unwrap()
        else {
            panic!("expected prepared delete")
        };
        assert_eq!(private_key_ids, vec![id]);
        assert_eq!(delete_without_export, Some(true));
    }
}
