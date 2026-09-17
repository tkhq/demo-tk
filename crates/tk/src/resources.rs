use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, from_slice, to_value};
use turnkey_client::generated::{
    immutable::activity::v1 as intent, services::coordinator::public::v1 as query,
};
use uuid::Uuid;

use crate::{
    auth::{ResolvedAuth, build_turnkey_client},
    errors::{InvalidInput, Malformed, MissingResource},
    operations::{OperationOutput, submit_activity},
};

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    List,
    Get {
        /// User to fetch.
        #[arg(long)]
        id: Uuid,
    },
    /// Create one or more users from a `CreateUsersIntentV4` parameters object.
    Create(BodyArgs),
    /// Update user name, email, phone, or tag membership.
    Update(BodyArgs),
    Delete {
        /// User to delete; repeat to delete several.
        #[arg(long = "id", required = true)]
        ids: Vec<Uuid>,
    },
    Tag {
        #[command(subcommand)]
        command: TagCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum TagCommand {
    List,
    Create(BodyArgs),
    Update(BodyArgs),
    Delete {
        /// Tag to delete; repeat to delete several.
        #[arg(long = "id", required = true)]
        ids: Vec<Uuid>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    List,
    Get {
        /// Policy to fetch.
        #[arg(long)]
        id: Uuid,
    },
    /// Create a policy from a `CreatePolicyIntentV3` parameters object.
    Create(BodyArgs),
    /// Create multiple policies from a parameters object containing policies.
    CreateBatch(BodyArgs),
    /// Update with policyEffect/policyCondition/policyConsensus field names.
    Update(BodyArgs),
    Delete {
        /// Policy to delete; repeat to delete several.
        #[arg(long = "id", required = true)]
        ids: Vec<Uuid>,
    },
    Evaluations {
        /// Activity whose policy evaluations to fetch.
        #[arg(long)]
        activity_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
pub enum ApiKeyCommand {
    List {
        #[arg(long)]
        user_id: Option<Uuid>,
    },
    /// Register public keys using `CreateApiKeysIntentV2` parameters.
    Register(BodyArgs),
    Delete {
        #[arg(long)]
        user_id: Uuid,
        /// API key to delete; repeat to delete several.
        #[arg(long = "id", required = true)]
        ids: Vec<Uuid>,
    },
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct BodyArgs {
    /// Inline JSON parameters (no activity envelope).
    #[arg(long)]
    input_json: Option<String>,
    /// Read JSON parameters from a file, or - for stdin.
    #[arg(long)]
    input_file: Option<PathBuf>,
}

pub enum PreparedResource {
    Query(Query),
    Mutation(Mutation),
}

pub enum Query {
    Users,
    User(Uuid),
    Tags,
    Policies,
    Policy(Uuid),
    Evaluations(Uuid),
    ApiKeys(Option<Uuid>),
}

pub enum Mutation {
    CreateUsers(intent::CreateUsersIntentV4),
    UpdateUser(intent::UpdateUserIntent),
    DeleteUsers(intent::DeleteUsersIntent),
    CreateTag(intent::CreateUserTagIntent),
    UpdateTag(intent::UpdateUserTagIntent),
    DeleteTags(intent::DeleteUserTagsIntent),
    CreatePolicy(intent::CreatePolicyIntentV3),
    CreatePolicies(intent::CreatePoliciesIntent),
    UpdatePolicy(intent::UpdatePolicyIntentV2),
    DeletePolicy(intent::DeletePolicyIntent),
    DeletePolicies(intent::DeletePoliciesIntent),
    RegisterKeys(intent::CreateApiKeysIntentV2),
    DeleteKeys(intent::DeleteApiKeysIntent),
}

impl BodyArgs {
    pub(crate) fn parse<T: DeserializeOwned + Serialize>(self) -> Result<T> {
        let bytes = match (self.input_json, self.input_file) {
            (Some(json), _) => json.into_bytes(),
            (None, Some(path)) if path.as_os_str() == "-" => {
                let mut bytes = Vec::new();
                io::stdin().read_to_end(&mut bytes).map_err(|error| {
                    Malformed::new("could not read JSON parameters from stdin", error)
                })?;
                bytes
            }
            (None, Some(path)) => fs::read(&path).map_err(|error| {
                Malformed::new(
                    format!("could not read JSON parameters from {}", path.display()),
                    error,
                )
            })?,
            (None, None) => unreachable!("clap requires exactly one parameters source"),
        };
        let mut value: Value = from_slice(&bytes)
            .map_err(|error| Malformed::new("parameters must be valid JSON", error))?;
        if !value.is_object() {
            return Err(InvalidInput("parameters must be a JSON object".into()).into());
        }
        normalize_ids(&mut value)?;
        let typed: T = T::deserialize(&value)
            .map_err(|error| Malformed::new("invalid operation parameters", error))?;
        let normalized = to_value(&typed)?;
        reject_dropped_fields(&value, &normalized, "parameters")?;
        Ok(typed)
    }
}

fn normalize_id(value: &mut Value, key: &str) -> Result<()> {
    let Some(id) = value.as_str() else {
        return Err(InvalidInput(format!("{key} must be a string")).into());
    };
    let id = Uuid::parse_str(id)
        .map_err(|error| Malformed::new(format!("invalid UUID in {key}"), error))?;
    *value = Value::String(id.to_string());
    Ok(())
}

fn normalize_ids(value: &mut Value) -> Result<()> {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if matches!(key.as_str(), "userId" | "userTagId" | "policyId") {
                    normalize_id(value, key)?;
                } else if matches!(
                    key.as_str(),
                    "userIds"
                        | "userTags"
                        | "userTagIds"
                        | "addUserIds"
                        | "removeUserIds"
                        | "apiKeyIds"
                        | "policyIds"
                ) {
                    let Some(ids) = value.as_array_mut() else {
                        return Err(InvalidInput(format!("{key} must be an array")).into());
                    };
                    for value in ids {
                        normalize_id(value, key)?;
                    }
                } else {
                    normalize_ids(value)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_ids(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_dropped_fields(input: &Value, normalized: &Value, path: &str) -> Result<()> {
    match (input, normalized) {
        (Value::Object(input), Value::Object(normalized)) => {
            for (key, value) in input {
                let Some(known) = normalized.get(key) else {
                    return Err(InvalidInput(format!("unsupported field {path}.{key}")).into());
                };
                reject_dropped_fields(value, known, &format!("{path}.{key}"))?;
            }
        }
        (Value::Array(input), Value::Array(normalized)) => {
            for (i, (value, known)) in input.iter().zip(normalized).enumerate() {
                reject_dropped_fields(value, known, &format!("{path}[{i}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl UserCommand {
    pub fn prepare(self) -> Result<PreparedResource> {
        Ok(match self {
            UserCommand::List => PreparedResource::Query(Query::Users),
            UserCommand::Get { id } => PreparedResource::Query(Query::User(id)),
            UserCommand::Create(body) => {
                let params: intent::CreateUsersIntentV4 = body.parse()?;
                if params.users.is_empty() {
                    return Err(InvalidInput("users must contain at least one user".into()).into());
                }
                PreparedResource::Mutation(Mutation::CreateUsers(params))
            }
            UserCommand::Update(body) => {
                PreparedResource::Mutation(Mutation::UpdateUser(body.parse()?))
            }
            UserCommand::Delete { ids } => {
                PreparedResource::Mutation(Mutation::DeleteUsers(intent::DeleteUsersIntent {
                    user_ids: ids.into_iter().map(|id| id.to_string()).collect(),
                }))
            }
            UserCommand::Tag { command } => match command {
                TagCommand::List => PreparedResource::Query(Query::Tags),
                TagCommand::Create(body) => {
                    PreparedResource::Mutation(Mutation::CreateTag(body.parse()?))
                }
                TagCommand::Update(body) => {
                    PreparedResource::Mutation(Mutation::UpdateTag(body.parse()?))
                }
                TagCommand::Delete { ids } => {
                    PreparedResource::Mutation(Mutation::DeleteTags(intent::DeleteUserTagsIntent {
                        user_tag_ids: ids.into_iter().map(|id| id.to_string()).collect(),
                    }))
                }
            },
        })
    }
}

impl PolicyCommand {
    pub fn prepare(self) -> Result<PreparedResource> {
        Ok(match self {
            PolicyCommand::List => PreparedResource::Query(Query::Policies),
            PolicyCommand::Get { id } => PreparedResource::Query(Query::Policy(id)),
            PolicyCommand::Create(body) => {
                PreparedResource::Mutation(Mutation::CreatePolicy(body.parse()?))
            }
            PolicyCommand::CreateBatch(body) => {
                let params: intent::CreatePoliciesIntent = body.parse()?;
                if params.policies.is_empty() {
                    return Err(
                        InvalidInput("policies must contain at least one policy".into()).into(),
                    );
                }
                PreparedResource::Mutation(Mutation::CreatePolicies(params))
            }
            PolicyCommand::Update(body) => {
                PreparedResource::Mutation(Mutation::UpdatePolicy(body.parse()?))
            }
            PolicyCommand::Delete { ids } => match ids.as_slice() {
                [only] => {
                    PreparedResource::Mutation(Mutation::DeletePolicy(intent::DeletePolicyIntent {
                        policy_id: only.to_string(),
                    }))
                }
                many => PreparedResource::Mutation(Mutation::DeletePolicies(
                    intent::DeletePoliciesIntent {
                        policy_ids: many.iter().map(ToString::to_string).collect(),
                    },
                )),
            },
            PolicyCommand::Evaluations { activity_id } => {
                PreparedResource::Query(Query::Evaluations(activity_id))
            }
        })
    }
}

impl ApiKeyCommand {
    pub fn prepare(self) -> Result<PreparedResource> {
        Ok(match self {
            ApiKeyCommand::List { user_id } => PreparedResource::Query(Query::ApiKeys(user_id)),
            ApiKeyCommand::Register(body) => {
                let params: intent::CreateApiKeysIntentV2 = body.parse()?;
                if params.api_keys.is_empty() {
                    return Err(InvalidInput(
                        "apiKeys must contain at least one public key".into(),
                    )
                    .into());
                }
                PreparedResource::Mutation(Mutation::RegisterKeys(params))
            }
            ApiKeyCommand::Delete { user_id, ids } => {
                PreparedResource::Mutation(Mutation::DeleteKeys(intent::DeleteApiKeysIntent {
                    user_id: user_id.to_string(),
                    api_key_ids: ids.into_iter().map(|id| id.to_string()).collect(),
                }))
            }
        })
    }
}

impl PreparedResource {
    pub async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        match self {
            Self::Query(query) => query.run(auth).await,
            Self::Mutation(mutation) => mutation.run(auth).await,
        }
    }
}

impl Mutation {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let (command, endpoint, kind, params) = match self {
            Self::CreateUsers(p) => (
                "user.create",
                "create_users",
                "ACTIVITY_TYPE_CREATE_USERS_V4",
                to_value(p)?,
            ),
            Self::UpdateUser(p) => (
                "user.update",
                "update_user",
                "ACTIVITY_TYPE_UPDATE_USER",
                to_value(p)?,
            ),
            Self::DeleteUsers(p) => (
                "user.delete",
                "delete_users",
                "ACTIVITY_TYPE_DELETE_USERS",
                to_value(p)?,
            ),
            Self::CreateTag(p) => (
                "user.tag.create",
                "create_user_tag",
                "ACTIVITY_TYPE_CREATE_USER_TAG",
                to_value(p)?,
            ),
            Self::UpdateTag(p) => (
                "user.tag.update",
                "update_user_tag",
                "ACTIVITY_TYPE_UPDATE_USER_TAG",
                to_value(p)?,
            ),
            Self::DeleteTags(p) => (
                "user.tag.delete",
                "delete_user_tags",
                "ACTIVITY_TYPE_DELETE_USER_TAGS",
                to_value(p)?,
            ),
            Self::CreatePolicy(p) => (
                "policy.create",
                "create_policy",
                "ACTIVITY_TYPE_CREATE_POLICY_V3",
                to_value(p)?,
            ),
            Self::CreatePolicies(p) => (
                "policy.create-batch",
                "create_policies",
                "ACTIVITY_TYPE_CREATE_POLICIES",
                to_value(p)?,
            ),
            Self::UpdatePolicy(p) => (
                "policy.update",
                "update_policy",
                "ACTIVITY_TYPE_UPDATE_POLICY_V2",
                to_value(p)?,
            ),
            Self::DeletePolicy(p) => (
                "policy.delete",
                "delete_policy",
                "ACTIVITY_TYPE_DELETE_POLICY",
                to_value(p)?,
            ),
            Self::DeletePolicies(p) => (
                "policy.delete",
                "delete_policies",
                "ACTIVITY_TYPE_DELETE_POLICIES",
                to_value(p)?,
            ),
            Self::RegisterKeys(p) => (
                "api-key.register",
                "create_api_keys",
                "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
                to_value(p)?,
            ),
            Self::DeleteKeys(p) => (
                "api-key.delete",
                "delete_api_keys",
                "ACTIVITY_TYPE_DELETE_API_KEYS",
                to_value(p)?,
            ),
        };
        submit_activity(&auth, command, endpoint, kind, &params).await
    }
}

impl Query {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
        let organization_id = auth.org_id.to_string();
        let (command, data) = match self {
            Self::Users => (
                "user.list",
                to_value(
                    client
                        .get_users(query::GetUsersRequest { organization_id })
                        .await?,
                )?,
            ),
            Self::User(id) => {
                let response = client
                    .get_user(query::GetUserRequest {
                        organization_id,
                        user_id: id.to_string(),
                    })
                    .await?;
                if response.user.is_none() {
                    return Err(MissingResource::new("user", id.to_string()).into());
                }
                ("user.get", to_value(response)?)
            }
            Self::Tags => (
                "user.tag.list",
                to_value(
                    client
                        .list_user_tags(query::ListUserTagsRequest { organization_id })
                        .await?,
                )?,
            ),
            Self::Policies => (
                "policy.list",
                to_value(
                    client
                        .get_policies(query::GetPoliciesRequest { organization_id })
                        .await?,
                )?,
            ),
            Self::Policy(id) => {
                let response = client
                    .get_policy(query::GetPolicyRequest {
                        organization_id,
                        policy_id: id.to_string(),
                    })
                    .await?;
                if response.policy.is_none() {
                    return Err(MissingResource::new("policy", id.to_string()).into());
                }
                ("policy.get", to_value(response)?)
            }
            Self::Evaluations(id) => (
                "policy.evaluations",
                to_value(
                    client
                        .get_policy_evaluations(query::GetPolicyEvaluationsRequest {
                            organization_id,
                            activity_id: id.to_string(),
                        })
                        .await?,
                )?,
            ),
            Self::ApiKeys(user_id) => (
                "api-key.list",
                to_value(
                    client
                        .get_api_keys(query::GetApiKeysRequest {
                            organization_id,
                            user_id: user_id.map(|id| id.to_string()),
                        })
                        .await?,
                )?,
            ),
        };
        Ok(OperationOutput::result(command, data))
    }
}

// Asserts on the classified error code.
#[cfg(test)]
#[allow(clippy::disallowed_types)]
mod tests {
    use super::*;
    use crate::errors::{ActivityError, ActivityErrorKind, Classification, ErrorCode, classify};
    use clap::Parser;
    use serde_json::{from_value, json, to_vec};
    use std::iter::once;
    use tempfile::NamedTempFile;
    use turnkey_api_key_stamper::TurnkeyP256ApiKey;
    use turnkey_client::generated::external::activity::v1 as activity;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const ID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "22222222-2222-4222-8222-222222222222";

    fn auth(server: &MockServer) -> ResolvedAuth {
        ResolvedAuth::for_tests(ID, &server.uri(), TurnkeyP256ApiKey::generate())
    }

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommand,
    }

    #[derive(Subcommand)]
    enum TestCommand {
        User {
            #[command(subcommand)]
            command: UserCommand,
        },
        Policy {
            #[command(subcommand)]
            command: PolicyCommand,
        },
        ApiKey {
            #[command(subcommand)]
            command: ApiKeyCommand,
        },
    }

    fn prepare(args: &[&str]) -> Result<PreparedResource> {
        let cli = TestCli::try_parse_from(once("tk").chain(args.iter().copied()))?;
        match cli.command {
            TestCommand::User { command } => command.prepare(),
            TestCommand::Policy { command } => command.prepare(),
            TestCommand::ApiKey { command } => command.prepare(),
        }
    }

    #[test]
    fn malformed_and_unsupported_inputs_fail_before_auth() {
        for args in [
            vec!["user", "get", "--id", "not-a-uuid"],
            vec!["user", "delete"],
            vec!["policy", "delete"],
            vec!["policy", "list", "--cursor", "invented"],
            vec![
                "policy",
                "create",
                "--input-json",
                "{}",
                "--input-file",
                "-",
            ],
            vec!["policy", "create"],
            vec!["user", "create", "--input-json", r#"{"users":[]}"#],
            vec![
                "api-key",
                "register",
                "--input-json",
                r#"{"userId":"bad","apiKeys":[]}"#,
            ],
            vec![
                "policy",
                "update",
                "--input-json",
                r#"{"policyId":"11111111-1111-4111-8111-111111111111","effect":"EFFECT_ALLOW"}"#,
            ],
            vec![
                "user",
                "create",
                "--input-json",
                r#"{"users":[{"userName":"agent","apiKeys":[{"apiKeyName":"key","publicKey":"03ab","curveType":"API_KEY_CURVE_P256","privateKey":"secret"}]}]}"#,
            ],
        ] {
            assert!(
                prepare(&args).is_err(),
                "input unexpectedly accepted: {args:?}"
            );
        }
    }

    #[test]
    fn policy_file_preserves_exact_expressions() {
        let file = NamedTempFile::new().unwrap();
        let params = json!({
            "policyName": "agent policy",
            "effect": "EFFECT_ALLOW",
            "condition": "activity.action == 'SIGN' &&\n  wallet.id == 'literal'",
            "consensus": "approvers.any(user, user.id == 'literal')",
            "notes": "Reviewed policy",
            "time": null
        });
        fs::write(file.path(), to_vec(&params).unwrap()).unwrap();
        let body = file.path().display().to_string();
        let command = prepare(&["policy", "create", "--input-file", &body]).unwrap();
        let PreparedResource::Mutation(Mutation::CreatePolicy(actual)) = command else {
            panic!("expected prepared policy creation")
        };
        assert_eq!(to_value(actual).unwrap(), params);
    }

    #[tokio::test]
    async fn all_mutations_use_versioned_envelopes_and_submit_once() {
        let user_body = r#"{"users":[{"userName":"agent","userTags":["11111111-1111-4111-8111-111111111111"]}]}"#;
        let update_user =
            r#"{"userId":"11111111-1111-4111-8111-111111111111","userName":"renamed"}"#;
        let tag_body =
            r#"{"userTagName":"agents","userIds":["11111111-1111-4111-8111-111111111111"]}"#;
        let update_tag = r#"{"userTagId":"11111111-1111-4111-8111-111111111111","addUserIds":["22222222-2222-4222-8222-222222222222"]}"#;
        let policy_body = r#"{"policyName":"agent","effect":"EFFECT_ALLOW","condition":"true","consensus":"true","notes":"test"}"#;
        let policies_body =
            r#"{"policies":[{"policyName":"agent","effect":"EFFECT_ALLOW","notes":"test"}]}"#;
        let update_policy = r#"{"policyId":"11111111-1111-4111-8111-111111111111","policyEffect":"EFFECT_DENY","policyCondition":"true"}"#;
        let keys_body = r#"{"userId":"11111111-1111-4111-8111-111111111111","apiKeys":[{"apiKeyName":"agent","publicKey":"03ab","curveType":"API_KEY_CURVE_P256"}]}"#;
        let cases = [
            (
                vec!["user", "create", "--input-json", user_body],
                "create_users",
                "ACTIVITY_TYPE_CREATE_USERS_V4",
            ),
            (
                vec!["user", "update", "--input-json", update_user],
                "update_user",
                "ACTIVITY_TYPE_UPDATE_USER",
            ),
            (
                vec!["user", "delete", "--id", ID],
                "delete_users",
                "ACTIVITY_TYPE_DELETE_USERS",
            ),
            (
                vec!["user", "tag", "create", "--input-json", tag_body],
                "create_user_tag",
                "ACTIVITY_TYPE_CREATE_USER_TAG",
            ),
            (
                vec!["user", "tag", "update", "--input-json", update_tag],
                "update_user_tag",
                "ACTIVITY_TYPE_UPDATE_USER_TAG",
            ),
            (
                vec!["user", "tag", "delete", "--id", ID],
                "delete_user_tags",
                "ACTIVITY_TYPE_DELETE_USER_TAGS",
            ),
            (
                vec!["policy", "create", "--input-json", policy_body],
                "create_policy",
                "ACTIVITY_TYPE_CREATE_POLICY_V3",
            ),
            (
                vec!["policy", "create-batch", "--input-json", policies_body],
                "create_policies",
                "ACTIVITY_TYPE_CREATE_POLICIES",
            ),
            (
                vec!["policy", "update", "--input-json", update_policy],
                "update_policy",
                "ACTIVITY_TYPE_UPDATE_POLICY_V2",
            ),
            (
                vec!["policy", "delete", "--id", ID],
                "delete_policy",
                "ACTIVITY_TYPE_DELETE_POLICY",
            ),
            (
                vec!["policy", "delete", "--id", ID, "--id", OTHER],
                "delete_policies",
                "ACTIVITY_TYPE_DELETE_POLICIES",
            ),
            (
                vec!["api-key", "register", "--input-json", keys_body],
                "create_api_keys",
                "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
            ),
            (
                vec!["api-key", "delete", "--user-id", ID, "--id", OTHER],
                "delete_api_keys",
                "ACTIVITY_TYPE_DELETE_API_KEYS",
            ),
        ];
        for (args, endpoint, kind) in cases {
            for status in [
                "ACTIVITY_STATUS_PENDING",
                "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                "ACTIVITY_STATUS_REJECTED",
                "ACTIVITY_STATUS_FAILED",
                "ACTIVITY_STATUS_COMPLETED",
            ] {
                let server = MockServer::start().await;
                let expected: activity::Activity = from_value(json!({
                    "id": OTHER, "organizationId": ID, "type": kind,
                    "status": status, "fingerprint": "fixture"
                }))
                .unwrap();
                Mock::given(method("POST"))
                    .and(path(format!("/public/v1/submit/{endpoint}")))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(json!({"activity": expected})),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
                let result = prepare(&args).unwrap().run(auth(&server)).await;
                match result {
                    Ok(output) => {
                        assert!(!matches!(
                            status,
                            "ACTIVITY_STATUS_REJECTED" | "ACTIVITY_STATUS_FAILED"
                        ));
                        assert_eq!(
                            to_value(output).unwrap()["data"]["activity"],
                            to_value(expected).unwrap()
                        );
                    }
                    Err(error) => {
                        assert!(matches!(
                            status,
                            "ACTIVITY_STATUS_REJECTED" | "ACTIVITY_STATUS_FAILED"
                        ));
                        let failure = error.downcast_ref::<ActivityError>().unwrap();
                        assert_eq!(failure.kind(), ActivityErrorKind::NotCompleted);
                        assert_eq!(
                            failure.activity(),
                            Some(&json!({"id": OTHER, "status": status}))
                        );
                    }
                }
                let requests = server.received_requests().await.unwrap();
                assert_eq!(requests.len(), 1);
                let body: Value = from_slice(&requests[0].body).unwrap();
                assert_eq!(body["type"], kind);
                assert_eq!(body["organizationId"], ID);
                assert!(
                    body["timestampMs"]
                        .as_str()
                        .unwrap()
                        .parse::<u128>()
                        .unwrap()
                        > 0
                );
                assert!(requests[0].headers.contains_key("x-stamp"));
                if endpoint == "update_policy" {
                    assert_eq!(
                        body["parameters"],
                        json!({
                            "policyId": ID, "policyName": null, "policyEffect": "EFFECT_DENY",
                            "policyCondition": "true", "policyConsensus": null,
                            "policyNotes": null, "time": null
                        })
                    );
                }
                server.verify().await;
            }
        }
    }

    #[tokio::test]
    async fn missing_lookup_preserves_typed_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/public/v1/query/get_user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"user": null})))
            .mount(&server)
            .await;
        let result = prepare(&["user", "get", "--id", ID])
            .unwrap()
            .run(auth(&server))
            .await;
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), format!("user not found: {ID}"));
        assert_eq!(
            classify(&error),
            Classification {
                code: ErrorCode::NotFound,
                http_status: None,
            }
        );
    }
    #[tokio::test]
    async fn mutation_transport_refuses_redirects_and_preserves_uncertain_outcomes() {
        for (template, expected) in [
            (
                ResponseTemplate::new(307).insert_header("Location", "/redirect-target"),
                Classification {
                    code: ErrorCode::ApiError,
                    http_status: Some(307),
                },
            ),
            (
                ResponseTemplate::new(308).insert_header("Location", "/redirect-target"),
                Classification {
                    code: ErrorCode::ApiError,
                    http_status: Some(308),
                },
            ),
            (
                ResponseTemplate::new(200).set_body_string("not JSON"),
                Classification {
                    code: ErrorCode::SubmissionUnknown,
                    http_status: None,
                },
            ),
            (
                ResponseTemplate::new(200).set_body_json(json!({})),
                Classification {
                    code: ErrorCode::SubmissionUnknown,
                    http_status: None,
                },
            ),
            (
                ResponseTemplate::new(401).set_body_json(json!({"message":"denied"})),
                Classification {
                    code: ErrorCode::Unauthorized,
                    http_status: Some(401),
                },
            ),
            (
                ResponseTemplate::new(403).set_body_json(json!({"message":"denied"})),
                Classification {
                    code: ErrorCode::Unauthorized,
                    http_status: Some(403),
                },
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/public/v1/submit/delete_users"))
                .respond_with(template)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(path("/redirect-target"))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(&server)
                .await;
            let error = prepare(&["user", "delete", "--id", ID])
                .unwrap()
                .run(auth(&server))
                .await
                .unwrap_err();
            assert_eq!(classify(&error), expected);
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
            server.verify().await;
        }
    }
}
