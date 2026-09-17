//! Exports a set of secrets as dotenv lines for a process's environment.

use anyhow::Result;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt::Write;
use std::mem;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::SecretOutput;
use super::export::{Binding, Exported, Secret, export_value, list_all};
use super::input::{UniqueKeyValues, quorum_for};
use crate::auth::{ResolvedAuth, state_dir};
use crate::errors::{InvalidInput, PendingApprovals, PendingExport};
use crate::operations::OperationOutput;

const COMMAND: &str = "secret.env";

/// Returns true when a secret has a name matching `name_prefix` and carries
/// every requested static property.
fn matches(
    secret: &Secret,
    properties: &BTreeMap<String, String>,
    name_prefix: Option<&str>,
) -> bool {
    let Some(name) = secret.name.as_deref() else {
        return false;
    };
    if name_prefix.is_some_and(|prefix| !name.starts_with(prefix)) {
        return false;
    }
    properties.iter().all(|(key, value)| {
        secret
            .static_properties
            .iter()
            .any(|property| property.key == *key && property.value == *value)
    })
}

fn select(secrets: Vec<(String, Uuid)>) -> Result<BTreeMap<String, (String, Uuid)>> {
    let mut by_var: BTreeMap<String, (String, Uuid)> = BTreeMap::new();
    for (name, id) in secrets {
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
                entry.insert((name, id));
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
    let selected = select(
        list_all(&auth, |secret| {
            matches(secret, &properties, name_prefix.as_deref())
        })
        .await?
        .into_iter()
        .filter_map(|secret| secret.name.map(|name| (name, secret.id)))
        .collect(),
    )?;
    if selected.is_empty() {
        return Err(InvalidInput("no secrets match the selection".into()).into());
    }

    let binding = Binding::of(&auth);
    let mut exported = Vec::new();
    let mut pending = Vec::new();
    let mut env: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for (var, (name, secret_id)) in selected {
        let attempt = export_value(
            &state_dir,
            &quorum,
            &auth,
            &binding,
            secret_id,
            UniqueKeyValues::empty(),
        )
        .await?;
        match attempt {
            Exported::Pending {
                record: _,
                activity_id,
            } => {
                pending.push(PendingExport {
                    name,
                    secret_id,
                    var,
                    activity_id,
                });
            }
            Exported::Completed { record: _, value } => {
                exported.push(json!({"name": name, "secretId": secret_id, "var": var}));
                env.insert(var, value);
            }
        }
    }
    if !pending.is_empty() {
        return Err(PendingApprovals { pending }.into());
    }

    let mut plain = Zeroizing::new(String::new());
    let mut values = Map::new();
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
    fn matches_by_prefix_and_every_property() {
        let unilateral = BTreeMap::from([("consensus".to_owned(), "unilateral".to_owned())]);
        let secrets = vec![
            secret("hermes/API_TOKEN", &[("consensus", "unilateral")]),
            secret("hermes/OTHER", &[("consensus", "approval")]),
            secret("other/API_TOKEN", &[("consensus", "unilateral")]),
            Secret {
                id: Uuid::new_v4(),
                name: None,
                static_properties: vec![],
            },
        ];
        let kept: Vec<(String, Uuid)> = secrets
            .into_iter()
            .filter(|secret| matches(secret, &unilateral, Some("hermes/")))
            .filter_map(|secret| secret.name.map(|name| (name, secret.id)))
            .collect();
        let selected = select(kept).unwrap();
        let vars: Vec<&str> = selected.keys().map(String::as_str).collect();
        assert_eq!(vars, ["API_TOKEN"]);
        assert_eq!(selected["API_TOKEN"].0, "hermes/API_TOKEN");
    }

    #[test]
    fn rejects_bad_variable_names_and_duplicates() {
        let error = select(vec![("hermes/not-a-var".to_owned(), Uuid::new_v4())]).unwrap_err();
        let InvalidInput(message) = error
            .downcast_ref::<InvalidInput>()
            .expect("expected InvalidInput");
        assert_eq!(
            message,
            "secret hermes/not-a-var does not end in a valid environment variable name; \
             expected <prefix>/<VAR>"
        );
        let error = select(vec![
            ("a/TOKEN".to_owned(), Uuid::new_v4()),
            ("b/TOKEN".to_owned(), Uuid::new_v4()),
        ])
        .unwrap_err();
        let InvalidInput(message) = error
            .downcast_ref::<InvalidInput>()
            .expect("expected InvalidInput");
        assert_eq!(
            message,
            "secrets a/TOKEN and b/TOKEN both map to variable TOKEN; narrow the selection"
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
