# Policy Builder Syntax

```rs
policy_builder! {
    // specifies which builder to use
    USE builder; // optional

    // can be used to set fields of the policy config
    CONFIG { // optional
        max_rules: N,
        max_condition_depth: N,
        max_context_attrs: N
        ...
    };

    // rules..
    <ALLOW|DENY> <match_pattern> [WHERE { <condition> }] => <reason_code>;
}
```

## Match Pattern

```ruby
# wildcard (* also works)
ANY
# tuple style
(<principal> <action> <resource>)
# struct style
{principal:<principal>, action:<action>, resource:<resource>}
```

## Field Values in Match Patterns

Each field (principal, action, resource) can be:

- **Literal string**: `"value"`
- **Array of strings**: `["value1", "value2"]`
- **Wildcard**: `*` or `ANY`

## Conditions

```rs
NOT true                                   // not
role EQ "admin"                            // equals
status NEQ "banned"                        // not equals
true AND false                             // and
true OR false                              // or
(NOT true OR role EQ "mod") AND active EQ true  // grouped
```

## Precedence

| Op          | Meaning | Precedence  |
| ----------- | ------- | ----------- |
| `()`        | Group   | 1 (highest) |
| `NOT`       | Negate  | 2           |
| `EQ`, `NEQ` | Compare | 3           |
| `AND`, `OR` | Logic   | 4 (lowest)  |

## Reason Codes

The reason code can be either a number or a predefined constant.

```rs
ALLOW ANY => 1;

ALLOW ANY => SOME_CONSTANT;
```

## Full Form Example

```rust
policy_builder! {
    USE external_builder;

    CONFIG {
        max_rules: 100,
        max_condition_depth: 5,
        max_context_attrs: 50
    };

    DENY {
        principal: ["banned"],
        action: *,
        resource: *
    } => 1;

    ALLOW ANY
        WHERE {
            role EQ "admin"
        } => SOME_CONSTANT;

    ALLOW {
        action: ["read","list"],
        principal: *,
        resource: *
    } WHERE {
        role EQ "member"
    } => 3;
}
```

## Rule Examples

```rust
// Wildcard
ALLOW ANY => 1;

ALLOW * => 1;

// Tuple Style
DENY ("eve" ANY *) => 2;

ALLOW (["alice","bob"] ["read","write"] *) => 3;

// Struct Style
ALLOW { principal: "alice", action: "read", resource: * } => 4;

// Condition
ALLOW ANY WHERE { role EQ "admin" } => 5;

// Complex
DENY ANY WHERE { (banned EQ true OR suspended EQ true) AND NOT (admin EQ true) } => 6;
```
