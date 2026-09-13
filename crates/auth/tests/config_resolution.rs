//! Tests for auth config resolution.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use tempfile::tempdir;
use turnkey_auth::config::{
    Config, ConfigKey, default_config_dir_from_home, default_config_file_from_home,
};
use uuid::uuid;

#[test]
fn default_config_paths_are_derived_from_home() {
    let home = Path::new("/tmp/home");

    assert_eq!(
        default_config_dir_from_home(home),
        home.join(".config").join("turnkey").join("tk")
    );
    assert_eq!(
        default_config_file_from_home(home),
        home.join(".config")
            .join("turnkey")
            .join("tk")
            .join("tk.toml")
    );
}

#[tokio::test]
async fn config_resolution_prefers_env_over_global_over_default() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");
    fs::write(
        &config_path,
        r#"[turnkey]
organizationId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
apiPublicKey = "file-pub"
apiPrivateKey = "file-priv"
privateKeyId = "file-key"
    "#,
    )
    .unwrap();

    let env = BTreeMap::from([
        (
            "TURNKEY_ORGANIZATION_ID".to_string(),
            "11111111-2222-4333-8444-555555555555".to_string(),
        ),
        ("TURNKEY_API_PUBLIC_KEY".to_string(), "env-pub".to_string()),
        (
            "TURNKEY_API_PRIVATE_KEY".to_string(),
            "env-priv".to_string(),
        ),
        ("TURNKEY_PRIVATE_KEY_ID".to_string(), "env-key".to_string()),
    ]);

    let config = Config::resolve_from_map(&config_path, &env).await.unwrap();

    assert_eq!(
        config,
        Config {
            organization_id: uuid!("11111111-2222-4333-8444-555555555555"),
            api_public_key: "env-pub".to_string(),
            api_private_key: "env-priv".to_string(),
            private_key_id: Some("env-key".to_string()),
            api_base_url: "https://api.turnkey.com".to_string(),
        }
    );
}

#[tokio::test]
async fn config_resolution_does_not_require_private_key_id() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");
    fs::write(
        &config_path,
        r#"[turnkey]
organizationId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
apiPublicKey = "file-pub"
apiPrivateKey = "file-priv"
    "#,
    )
    .unwrap();

    let env = BTreeMap::new();
    let config = Config::resolve_from_map(&config_path, &env).await.unwrap();

    assert_eq!(
        config,
        Config {
            organization_id: uuid!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
            api_public_key: "file-pub".to_string(),
            api_private_key: "file-priv".to_string(),
            private_key_id: None,
            api_base_url: "https://api.turnkey.com".to_string(),
        }
    );
}

#[test]
fn every_config_key_round_trips_through_its_dotted_name() {
    for key in ConfigKey::ALL {
        assert_eq!(key.to_string().parse::<ConfigKey>().unwrap(), key);
    }
}

#[test]
fn an_unknown_name_is_not_a_config_key() {
    let error = "not.a.key".parse::<ConfigKey>().unwrap_err();

    assert_eq!(
        error.to_string(),
        "unsupported config key: not.a.key; supported keys: turnkey.organizationId, turnkey.apiPublicKey, turnkey.apiPrivateKey, turnkey.privateKeyId, turnkey.apiBaseUrl"
    );
}
