use gate0::{Policy, PolicyConfig, ReasonCode};

use gate0_dsl::policy_builder;
use insta::assert_debug_snapshot;

#[test]
fn test_simple_any_rules() {
    const REASON_ONE: ReasonCode = ReasonCode(1);
    const REASON_TWO: ReasonCode = ReasonCode(2);
    const REASON_THREE: ReasonCode = ReasonCode(3);
    let policy = policy_builder![
        // comment test
        ALLOW *   => 1;
        ALLOW *   => REASON_ONE;

        ALLOW ANY => 2;
        ALLOW ANY => REASON_TWO;

        DENY  *   => 3;
        DENY  ANY => REASON_THREE;
    ]
    .build()
    .unwrap();

    insta::assert_debug_snapshot!(policy);
}

#[test]
fn test_simple_tuple_rules() {
    const REASON_ONE: ReasonCode = ReasonCode(1);
    const REASON_TWO: ReasonCode = ReasonCode(2);
    let policy = policy_builder![
        ALLOW ("alice" "read"  "doc1") => 1;
        ALLOW ("bob"   "write" "doc2") => REASON_ONE;

        DENY  ("eve" * ANY) => 2;
        DENY  (["eve", "carl"] "write" *) => 2;
        DENY  ("mallory" "delete" "doc3") => REASON_TWO;
    ]
    .build()
    .unwrap();

    insta::assert_debug_snapshot!(policy);
}

#[test]
fn test_field_rules() {
    const REASON_ONE: ReasonCode = ReasonCode(1);
    const REASON_TWO: ReasonCode = ReasonCode(2);
    let policy = policy_builder![
        ALLOW {
            principal: "alice",
            action:    "read",
            resource:  "doc1",
        } => 1;

        ALLOW {
            principal: ["bob", "carl"],
            action:    ["write", "update"],
            resource:  ANY,
        } => REASON_ONE;

        DENY {
            principal: "eve",
            action:    *,
            resource:  ANY,
        } => 2;

        DENY {
            principal: ["mallory", "trent"],
            action:    "delete",
            resource:  ["doc2", "doc3"],
        } => REASON_TWO;
    ]
    .build()
    .unwrap();

    insta::assert_debug_snapshot!(policy);
}

#[test]
fn test_mixed_rules() {
    const REASON_TWO: ReasonCode = ReasonCode(2);
    const REASON_THREE: ReasonCode = ReasonCode(3);
    let policy = policy_builder![
        ALLOW * => 1;
        ALLOW ("alice" "read" "doc1") => REASON_TWO;
        DENY {
            principal: "eve",
            action:    *,
            resource:  ANY,
        } => REASON_THREE;
    ]
    .build()
    .unwrap();

    insta::assert_debug_snapshot!(policy);
}

#[test]
fn test_config() {
    let policy = policy_builder![
        CONFIG {
            max_rules: 500,
            max_condition_depth: 5,
        };
    ]
    .build()
    .unwrap();

    assert_eq!(policy.config().max_rules, 500);
    assert_eq!(policy.config().max_condition_depth, 5);
}

#[test]
fn test_where() {
    let policy = policy_builder![
        ALLOW ANY
            WHERE { role EQ "admin" } => 1;

        ALLOW ANY
            WHERE { "role" NEQ "admin" } => 1;

        ALLOW ANY
            WHERE { NOT (role EQ "admin" OR true) } => 1;

        ALLOW ANY
            WHERE { NOT ((role NEQ "admin") AND true) } => 2;

        // same as (NOT true) AND true
        ALLOW ANY
            WHERE { NOT true AND true } => 1;
    ]
    .build()
    .unwrap();

    insta::assert_debug_snapshot!(policy);
}

#[test]
fn test_external_builder() {
    let builder = Policy::builder().config(PolicyConfig {
        max_rules: 200,
        ..PolicyConfig::default()
    });
    let policy = policy_builder![
        USE builder;
    ]
    .build()
    .unwrap();
    assert_debug_snapshot!(policy);
}
