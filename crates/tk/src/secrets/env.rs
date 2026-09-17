//! Exports a set of secrets as dotenv lines for a process's environment.

use anyhow::Result;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt::Write;
use std::mem;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::SecretOutput;
use super::export::{Exported, Secret, export_value, list_all};
use super::input::{UniqueKeyValues, quorum_for};
use crate::auth::{ResolvedAuth, state_dir};
use crate::errors::{InvalidInput, PendingApprovals};
use crate::operations::OperationOutput;

const COMMAND: &str = "secret.env";

fn select(
    secrets: Vec<Secret>,
    properties: &BTreeMap<String, String>,
    name_prefix: Option<&str>,
) -> Result<BTreeMap<String, (String, Uuid)>> {
    let mut by_var: BTreeMap<String, (String, Uuid)> = BTreeMap::new();
    for secret in secrets {
        let Some(name) = secret.name else { continue };
        if name_prefix.is_some_and(|prefix| !name.starts_with(prefix)) {
            continue;
        }
        let has_all = properties.iter().all(|(key, value)| {
            secret
                .static_properties
                .iter()
                .any(|property| property.key == *key && property.value == *value)
        });
        if !has_all {
            continue;
        }
        let var = name
            .rsplit_once('/')
            .map_or(name.as_str(), |(_, var)| var)
            .to_owned();
        let valid = var
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(InvalidInput(format!(
                "secret {name} does not end in a valid environment variable name; expected <prefix>/<VAR>"
            ))
            .into());
        }
        match by_var.entry(var) {
            Entry::Occupied(entry) => {
                let (other, _) = entry.get();
                let var = entry.key();
                return Err(InvalidInput(format!(
                    "secrets {other} and {name} both map to variable {var}; narrow the selection"
                ))
                .into());
            }
            Entry::Vacant(entry) => {
                entry.insert((name, secret.id));
            }
        }
    }
    Ok(by_var)
}

/// Renders one dotenv line into `out`, quoting only when the value needs it.
fn line(out: &mut String, var: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0', '\'']) {
        return Err(InvalidInput(format!(
            "value of {var} contains a newline, NUL, or single quote and cannot be written as a dotenv line"
        ))
        .into());
    }
    let bare = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:+=@,-".contains(c));
    if bare {
        write!(out, "{var}={value}")?;
    } else {
        write!(out, "{var}='{value}'")?;
    }
    Ok(())
}

pub(super) async fn run(
    auth: ResolvedAuth,
    properties: UniqueKeyValues,
    name_prefix: Option<String>,
) -> Result<SecretOutput> {
    let quorum = quorum_for(auth.api_base_url.as_str())?;
    let state_dir = state_dir()?;
    let properties: BTreeMap<String, String> = properties.into();
    let selected = select(list_all(&auth).await?, &properties, name_prefix.as_deref())?;
    if selected.is_empty() {
        return Err(InvalidInput("no secrets match the selection".into()).into());
    }

    let mut exported = Vec::new();
    let mut pending = Vec::new();
    let mut env: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for (var, (name, secret_id)) in selected {
        let attempt = export_value(
            &state_dir,
            &quorum,
            &auth,
            secret_id,
            UniqueKeyValues::empty(),
        )
        .await?;
        match attempt {
            Exported::Pending { record } => {
                let entry = json!({
                    "name": &name,
                    "secretId": secret_id,
                    "var": var,
                    "activityId": record.data()["activity"]["id"],
                });
                pending.push((name, entry));
            }
            Exported::Completed { record: _, value } => {
                exported.push(json!({"name": name, "secretId": secret_id, "var": var}));
                env.insert(var, value);
            }
        }
    }
    if !pending.is_empty() {
        let (names, pending): (Vec<String>, Vec<Value>) = pending.into_iter().unzip();
        return Err(PendingApprovals {
            message: format!(
                "{} secret export(s) await approval: {}; approve them and run the same command again",
                pending.len(),
                names.join(", ")
            ),
            pending: Value::Array(pending),
        }
        .into());
    }

    let mut plain = Zeroizing::new(String::new());
    let mut values = serde_json::Map::new();
    for (var, mut value) in env {
        if !plain.is_empty() {
            plain.push('\n');
        }
        line(&mut plain, &var, &value)?;
        values.insert(var, Value::String(mem::take(&mut *value)));
    }
    Ok(SecretOutput {
        record: OperationOutput::result(
            COMMAND,
            json!({"exported": exported, "pending": [], "env": values}),
        ),
        plain: Some(plain),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use turnkey_client::generated::immutable::models::v1::KeyValue;

    fn secret(name: &str, properties: &[(&str, &str)]) -> Secret {
        Secret {
            id: Uuid::new_v4(),
            name: Some(name.into()),
            static_properties: properties
                .iter()
                .map(|(key, value)| KeyValue {
                    key: (*key).into(),
                    value: (*value).into(),
                })
                .collect(),
        }
    }

    #[test]
    fn selects_by_prefix_and_every_property() {
        let unilateral = BTreeMap::from([("consensus".to_owned(), "unilateral".to_owned())]);
        let secrets = vec![
            secret("hermes/API_TOKEN", &[("consensus", "unilateral")]),
            secret("hermes/OTHER", &[("consensus", "approval")]),
            secret("other/API_TOKEN", &[("consensus", "unilateral")]),
        ];
        let selected = select(secrets, &unilateral, Some("hermes/")).unwrap();
        let vars: Vec<&str> = selected.keys().map(String::as_str).collect();
        assert_eq!(vars, ["API_TOKEN"]);
        assert_eq!(selected["API_TOKEN"].0, "hermes/API_TOKEN");
    }

    #[test]
    fn rejects_bad_variable_names_and_duplicates() {
        let none = BTreeMap::new();
        let error = select(
            vec![secret("hermes/not-a-var", &[])],
            &none,
            Some("hermes/"),
        )
        .unwrap_err();
        assert!(error.downcast_ref::<InvalidInput>().is_some(), "{error}");
        let error = select(
            vec![secret("a/TOKEN", &[]), secret("b/TOKEN", &[])],
            &none,
            None,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("both map to variable TOKEN"),
            "{error}"
        );
    }

    #[test]
    fn quotes_only_when_needed_and_rejects_unwritable_values() {
        let render = |var, value| {
            let mut out = String::new();
            line(&mut out, var, value).map(|()| out)
        };
        assert_eq!(render("A", "tok-1.x/y:z+=@,").unwrap(), "A=tok-1.x/y:z+=@,");
        assert_eq!(render("A", "has space").unwrap(), "A='has space'");
        assert_eq!(render("A", "").unwrap(), "A=''");
        assert_eq!(
            render("A", "postgres://u:p@h/db?x=1").unwrap(),
            "A='postgres://u:p@h/db?x=1'"
        );
        for bad in ["a\nb", "a'b", "a\0b"] {
            assert!(render("A", bad).is_err(), "{bad:?} accepted");
        }
    }
}
