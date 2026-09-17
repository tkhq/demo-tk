//! Deletes a secret. Secrets are immutable, so rotation is a delete plus a
//! fresh import under the same name.

use anyhow::Result;
use serde_json::json;
use turnkey_client::generated::immutable::activity::v1::DeleteSecretsIntent;

use super::export::resolve_name;
use super::input::SecretRef;
use crate::auth::ResolvedAuth;
use crate::operations::{OperationOutput, submit_activity_with_id};

const COMMAND: &str = "secret.delete";

pub(super) async fn run(auth: ResolvedAuth, secret: SecretRef) -> Result<OperationOutput> {
    let secret_id = match secret {
        SecretRef::Id(id) => id,
        SecretRef::Name(name) => resolve_name(&auth, name).await?,
    };
    let (activity_id, submitted) = submit_activity_with_id(
        &auth,
        COMMAND,
        "delete_secrets",
        "ACTIVITY_TYPE_DELETE_SECRETS",
        &DeleteSecretsIntent {
            secret_ids: vec![secret_id.to_string()],
        },
    )
    .await?;
    let mut response = submitted.into_data();
    let activity = &mut response["activity"];
    Ok(OperationOutput::result(
        COMMAND,
        json!({
            "secretId": secret_id,
            "activity": {
                "id": activity_id,
                "status": activity["status"].take(),
                "type": activity["type"].take(),
                "result": activity["result"].take(),
            },
        }),
    ))
}
