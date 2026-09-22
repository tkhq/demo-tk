use crate::run::{
    AGENT_TAG, HUMAN_TAG, Run, allow_once, created_user_id, id_of, one_api_key, result, user_params,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
#[ignore]
fn user_lifecycle_from_input_json_and_stdin() {
    let run = Run::new();

    let json_name = run.name("user-json");
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--input-json",
            &user_params(&json_name, one_api_key(&run, &json_name)),
        ]),
        "user.create",
    );
    assert_eq!(
        created["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_USERS_V4"
    );
    let json_user = created_user_id(&created);

    let stdin_name = run.name("user-stdin");
    let created = run.submit(
        run.admin()
            .args(["user", "create", "--input-file", "-"])
            .write_stdin(user_params(&stdin_name, one_api_key(&run, &stdin_name))),
        "user.create",
    );
    let stdin_user = created_user_id(&created);

    for (id, name) in [(&json_user, &json_name), (&stdin_user, &stdin_name)] {
        let got = run.ok(run.admin().args(["user", "get", id]));
        assert_eq!(got["command"], "user.get");
        assert_eq!(got["data"]["user"]["userId"], *id);
        assert_eq!(got["data"]["user"]["userName"], *name);
    }
    let list = run.ok(run.admin().args(["user", "list"]));
    assert_eq!(list["command"], "user.list");
    let listed: Vec<&str> = list["data"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["userId"].as_str().unwrap())
        .collect();
    assert!(listed.contains(&json_user.as_str()));
    assert!(listed.contains(&stdin_user.as_str()));

    let deleted = run.submit(
        run.admin().args(["user", "delete", &stdin_user]),
        "user.delete",
    );
    assert_eq!(
        result(&deleted, "deleteUsersResult")["userIds"],
        json!([stdin_user])
    );
    let missing = run.err(run.admin().args(["user", "get", &stdin_user]));
    assert_eq!(missing["code"], "not_found");
}

#[test]
#[ignore]
fn user_create_from_flags_resolves_tag_names_and_registers_anchor_and_expiring_keys() {
    let run = Run::new();
    let tag_name = run.name("agent");
    let tag_id = run.create_tag(&tag_name);

    let key = run.key();
    let public_key = hex::encode(key.compressed_public_key());
    let user_name = run.name("flag-user");

    // Turnkey requires one long-lived credential per user.
    let expiring_only = run.err(run.admin().args([
        "user",
        "create",
        "--user-name",
        &user_name,
        "--public-key",
        &public_key,
        "--expires-in",
        "2h",
    ]));
    assert_eq!(expiring_only["code"], "api_error", "{expiring_only}");
    assert_eq!(expiring_only["httpStatus"], 400, "{expiring_only}");

    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--user-name",
            &user_name,
            "--tag-name",
            &tag_name,
            "--public-key",
            &public_key,
            "--expires-in",
            "2h",
            "--anchor-key",
        ]),
        "user.create",
    );
    let user_id = created_user_id(&created);

    let got = run.ok(run.admin().args(["user", "get", &user_id]));
    assert_eq!(got["data"]["user"]["userName"], user_name);
    assert_eq!(got["data"]["user"]["userTags"], json!([tag_id]));
    let keys = run.ok(run.admin().args(["api-key", "list", "--user-id", &user_id]));
    let ours = keys["data"]["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["credential"]["publicKey"] == public_key)
        .unwrap_or_else(|| panic!("registered key missing: {keys}"));
    assert_eq!(ours["apiKeyName"], format!("{user_name}-key"));
    assert_eq!(ours["expirationSeconds"], "7200");
    let created: u64 = ours["createdAt"]["seconds"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        ours["expiresAt"],
        ((created + 7200) * 1000).to_string(),
        "{ours}"
    );
    let anchor = keys["data"]["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["apiKeyName"] == format!("{user_name}-anchor"))
        .unwrap_or_else(|| panic!("anchor key missing: {keys}"));
    assert_eq!(anchor["expirationSeconds"], Value::Null, "{anchor}");
    assert_eq!(keys["data"]["apiKeys"].as_array().unwrap().len(), 2);

    let whoami = run.ok(run.as_user(&key).arg("whoami"));
    assert_eq!(whoami["data"]["userId"], user_id);

    let unknown_tag = run.err(run.admin().args([
        "user",
        "create",
        "--user-name",
        &run.name("orphan"),
        "--tag-name",
        &run.name("no-such-tag"),
    ]));
    assert_eq!(unknown_tag["code"], "not_found", "{unknown_tag}");
}

struct Recipe {
    example: &'static str,
    filter: &'static str,
}

const TAGS: Recipe = Recipe {
    example: "inspecting.tags",
    filter: r#".data.userTags[] | "\(.tagId) \(.tagName)""#,
};
const AGENT_TAG_ID: Recipe = Recipe {
    example: "inspecting.tags",
    filter: r#".data.userTags[] | select(.tagName == "agent") | .tagId"#,
};
const TAGGED_USERS: Recipe = Recipe {
    example: "inspecting.tagged-users",
    filter: r#".data.users[] | select(.userTags | any(. == $tag)) | {userId, userName}"#,
};
const KEYS: Recipe = Recipe {
    example: "inspecting.keys",
    filter: r#".data.apiKeys[] | {apiKeyId, apiKeyName, publicKey: .credential.publicKey, expiresAt}"#,
};
const PERMANENT_KEYS: Recipe = Recipe {
    example: "inspecting.keys",
    filter: r#".data.apiKeys[] | select(.expiresAt == null) | .apiKeyId"#,
};
const PENDING: Recipe = Recipe {
    example: "inspecting.pending",
    filter: r#".data.items[] | select(.status == "ACTIVITY_STATUS_CONSENSUS_NEEDED") | {id, type, ageSeconds: (($now | tonumber) - (.createdAt.seconds | tonumber))}"#,
};
const NEXT_CURSOR: Recipe = Recipe {
    example: "inspecting.next-page",
    filter: ".data.nextCursor",
};
const VOTES: Recipe = Recipe {
    example: "inspecting.votes",
    filter: ".data.activity.votes[] | {userId, selection}",
};
const SECRETS: Recipe = Recipe {
    example: "inspecting.secrets",
    filter: r#".data.secrets[] | {name, properties: (.staticProperties | map("\(.key)=\(.value)"))}"#,
};
const POLICIES: Recipe = Recipe {
    example: "inspecting.policies",
    filter: r#".data.policies[] | select((.consensus // "") + (.condition // "") | contains($tag)) | {policyId, policyName, effect}"#,
};
const MINTED_BY: Recipe = Recipe {
    example: "inspecting.minted-by",
    filter: r#".data.items[] | select(any(.intent.createApiKeysIntentV2.apiKeys[]?, .intent.createUsersIntentV4.users[]?.apiKeys[]?; .publicKey == $pk)) | {id, type, status, minted: .createdAt.seconds, voters: [.votes[].userId]}"#,
};
const RECIPES: [&Recipe; 11] = [
    &TAGS,
    &AGENT_TAG_ID,
    &TAGGED_USERS,
    &KEYS,
    &PERMANENT_KEYS,
    &PENDING,
    &NEXT_CURSOR,
    &VOTES,
    &SECRETS,
    &POLICIES,
    &MINTED_BY,
];

/// Pipes a record through the `jq` binary on PATH and returns its stdout.
fn jq(record: &Value, args: &[&str]) -> String {
    let mut child = Command::new("jq")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("jq must be installed on PATH for this test: {error}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(record.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "jq {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn jq_values(record: &Value, args: &[&str]) -> Vec<Value> {
    serde_json::Deserializer::from_str(&jq(record, args))
        .into_iter::<Value>()
        .map(|value| value.unwrap())
        .collect()
}

fn jq_lines(record: &Value, filter: &str, args: &[&str]) -> Vec<String> {
    let mut argv = vec!["-r"];
    argv.extend_from_slice(args);
    argv.push(filter);
    jq(record, &argv).lines().map(str::to_owned).collect()
}

fn unix_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

#[test]
#[ignore]
fn inspecting_agents_questions() {
    let skill = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills/inspecting-agents/SKILL.md"),
    )
    .unwrap();
    for recipe in RECIPES {
        assert!(
            skill.contains(recipe.filter),
            "{} recipe drifted from SKILL.md: {}",
            recipe.example,
            recipe.filter
        );
    }

    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let human_tag = run.create_tag(HUMAN_TAG);
    let (agent_one_id, agent_one) = run.create_tagged_user("agent-one", AGENT_TAG);

    let agent_two_key = run.key();
    let agent_two_public_key = hex::encode(agent_two_key.compressed_public_key());
    let agent_two_name = run.name("agent-two");
    let created_two = run.submit(
        run.admin().args([
            "user",
            "create",
            "--user-name",
            &agent_two_name,
            "--tag-name",
            AGENT_TAG,
            "--public-key",
            &agent_two_public_key,
            "--expires-in",
            "2h",
            "--anchor-key",
        ]),
        "user.create",
    );
    let agent_two_id = created_user_id(&created_two);
    let minted_two_activity = id_of(&created_two);

    let (_human_id, _human) = run.create_tagged_user("human", HUMAN_TAG);
    let policy_name = run.name("agents-create-tags-with-approval");
    let policy_id = run.create_policy_from_flags(
        &policy_name,
        "allow",
        &allow_once(&agent_tag, &human_tag),
        "activity.type == 'ACTIVITY_TYPE_CREATE_USER_TAG'",
    );

    let pending = run.ok(run.as_user(&agent_one).args([
        "user",
        "tag",
        "create",
        "--name",
        &run.name("proposed"),
    ]));
    assert_eq!(pending["status"], "pending", "{pending}");
    let pending_id = id_of(&pending);

    let secret_name = run.name("service/API_TOKEN");
    run.submit(
        run.admin()
            .args([
                "secret",
                "import",
                &secret_name,
                "--property",
                "env=prod",
                "--property",
                "team=payments",
            ])
            .write_stdin("inspected-value"),
        "secret.import",
    );

    let registered_public_key = hex::encode(run.key().compressed_public_key());
    let registered = run.register_api_key(&agent_one_id, "ci-key", &registered_public_key);
    let registered_activity = id_of(&registered);
    let root_user_id = run.ok(run.admin().arg("whoami"))["data"]["userId"]
        .as_str()
        .unwrap()
        .to_owned();

    // inspecting.tags
    let tags = run.ok(run.admin().args(["user", "tag", "list"]));
    let listed: BTreeSet<String> = jq_lines(&tags, TAGS.filter, &[]).into_iter().collect();
    assert_eq!(
        listed,
        BTreeSet::from([
            format!("{agent_tag} {AGENT_TAG}"),
            format!("{human_tag} {HUMAN_TAG}"),
        ]),
        "{tags}"
    );
    assert_eq!(
        jq_lines(&tags, AGENT_TAG_ID.filter, &[]),
        [agent_tag.as_str()],
        "{tags}"
    );

    // inspecting.tagged-users
    let users = run.ok(run.admin().args(["user", "list"]));
    let tagged = jq_values(&users, &["--arg", "tag", &agent_tag, TAGGED_USERS.filter]);
    let tagged_ids: BTreeSet<&str> = tagged
        .iter()
        .map(|user| user["userId"].as_str().unwrap())
        .collect();
    assert_eq!(
        tagged_ids,
        BTreeSet::from([agent_one_id.as_str(), agent_two_id.as_str()]),
        "{users}"
    );
    assert!(
        tagged.iter().any(|user| user["userName"] == agent_two_name),
        "{tagged:?}"
    );

    // inspecting.keys
    let keys = run.ok(run
        .admin()
        .args(["api-key", "list", "--user-id", &agent_two_id]));
    let summarized = jq_values(&keys, &[KEYS.filter]);
    assert_eq!(summarized.len(), 2, "{keys}");
    let expiring = summarized
        .iter()
        .find(|key| key["publicKey"] == agent_two_public_key)
        .unwrap_or_else(|| panic!("expiring key missing: {keys}"));
    assert!(expiring["expiresAt"].is_string(), "{expiring}");
    let anchor = summarized
        .iter()
        .find(|key| key["apiKeyName"] == format!("{agent_two_name}-anchor"))
        .unwrap_or_else(|| panic!("anchor key missing: {keys}"));
    assert_eq!(anchor["expiresAt"], Value::Null, "{anchor}");
    assert_eq!(
        jq_lines(&keys, PERMANENT_KEYS.filter, &[]),
        [anchor["apiKeyId"].as_str().unwrap()],
        "{keys}"
    );

    // inspecting.pending
    let now = unix_now();
    let page = run.ok(run.admin().args(["activity", "list", "--limit", "50"]));
    let pending_items = jq_values(&page, &["--arg", "now", &now, PENDING.filter]);
    assert_eq!(pending_items.len(), 1, "{page}");
    assert_eq!(pending_items[0]["id"], pending_id, "{page}");
    assert_eq!(
        pending_items[0]["type"], "ACTIVITY_TYPE_CREATE_USER_TAG",
        "{page}"
    );
    let age = pending_items[0]["ageSeconds"].as_i64().unwrap();
    assert!((0..3600).contains(&age), "{}", pending_items[0]);

    // inspecting.votes
    let got = run.ok(run.admin().args(["activity", "get", &pending_id]));
    assert_eq!(
        jq_values(&got, &[VOTES.filter]),
        [json!({"userId": agent_one_id, "selection": "VOTE_SELECTION_APPROVED"})],
        "{got}"
    );

    // inspecting.secrets
    let secrets = run.ok(run.admin().args(["secret", "list", "--limit", "100"]));
    assert_eq!(
        jq_values(&secrets, &[SECRETS.filter]),
        [json!({"name": secret_name, "properties": ["env=prod", "team=payments"]})],
        "{secrets}"
    );
    assert_eq!(
        jq_lines(&secrets, NEXT_CURSOR.filter, &[]),
        ["null"],
        "{secrets}"
    );

    // inspecting.policies
    let policies = run.ok(run.admin().args(["policy", "list"]));
    assert_eq!(
        jq_values(&policies, &["--arg", "tag", &agent_tag, POLICIES.filter]),
        [json!({"policyId": policy_id, "policyName": policy_name, "effect": "EFFECT_ALLOW"})],
        "{policies}"
    );
    assert_eq!(
        jq_values(&policies, &["--arg", "tag", &agent_two_id, POLICIES.filter]),
        [] as [Value; 0],
        "{policies}"
    );

    // inspecting.next-page and inspecting.minted-by
    let first = run.ok(run.admin().args(["activity", "list", "--limit", "2"]));
    assert_eq!(
        jq_values(
            &first,
            &["--arg", "pk", &agent_two_public_key, MINTED_BY.filter]
        ),
        [] as [Value; 0],
        "first page alone must not attribute the key: {first}"
    );
    let mut pages = vec![first];
    loop {
        let cursor = jq_lines(pages.last().unwrap(), NEXT_CURSOR.filter, &[]);
        let [cursor] = cursor.as_slice() else {
            panic!("nextCursor is not one line: {cursor:?}");
        };
        if cursor == "null" {
            break;
        }
        pages.push(
            run.ok(run
                .admin()
                .args(["activity", "list", "--limit", "2", "--cursor", cursor])),
        );
    }
    assert!(pages.len() >= 3, "{} pages", pages.len());
    let ids: Vec<&str> = pages
        .iter()
        .flat_map(|page| page["data"]["items"].as_array().unwrap())
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "pages repeated an activity: {ids:?}"
    );
    assert_eq!(
        ids.iter().filter(|id| **id == pending_id).count(),
        1,
        "{ids:?}"
    );
    let pending_across_pages: Vec<Value> = pages
        .iter()
        .flat_map(|page| jq_values(page, &["--arg", "now", &now, PENDING.filter]))
        .collect();
    assert_eq!(pending_across_pages.len(), 1, "{pending_across_pages:?}");

    let minted = |public_key: &str| -> Vec<Value> {
        pages
            .iter()
            .flat_map(|page| jq_values(page, &["--arg", "pk", public_key, MINTED_BY.filter]))
            .collect()
    };
    let by_user_create = minted(&agent_two_public_key);
    assert_eq!(
        by_user_create,
        [json!({
            "id": minted_two_activity,
            "type": "ACTIVITY_TYPE_CREATE_USERS_V4",
            "status": "ACTIVITY_STATUS_COMPLETED",
            "minted": created_two["data"]["activity"]["createdAt"]["seconds"],
            "voters": [root_user_id],
        })],
        "{by_user_create:?}"
    );
    let by_register = minted(&registered_public_key);
    assert_eq!(by_register.len(), 1, "{by_register:?}");
    assert_eq!(by_register[0]["id"], registered_activity, "{by_register:?}");
    assert_eq!(
        by_register[0]["type"], "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        "{by_register:?}"
    );
    assert_eq!(
        minted(&hex::encode(run.key().compressed_public_key())),
        [] as [Value; 0]
    );
}
