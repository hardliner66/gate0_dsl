# gate0 DSL

This is crate provides a macro for gate0 to simplify the creation of gate0 policies, using a simple DSL, and a macro for creating contexts.

## Macros

### Context (`ctx!`)

The context macro simplifies creating a context to be evaluated alongside a request.

```rs
ctx! { "key" => value, ... }
```

### Policy Builder (`policy_builder!`)

The policy builder macro simplifies creating a policy, its config and rules.

```rs
policy_builder! {
    [CONFIG { ... }];         // Optional configuration block
    [USE <NAME_OF_BUILDER_VARIABLE>;]            // Optional external builder

    // Rule:
    <EFFECT> <MATCH_PATTERN> [WHERE { <CONDITION_EXPR> }] => REASON_CODE;
    // ... more rules
}
```

### Basic Syntax (ctx!)

```rs
ctx! {
    <string> => <value>,
    ...
}
```

## Example

This is how the `SaaS API` example looks like without the DSL:

```rs
// 1. Define the Policy
let policy = Policy::builder()
    // Rule: Admins can do anything
    .rule(Rule::new(
        Effect::Allow,
        Target::any(),
        Some(Condition::Equals {
            attr: "role",
            value: Value::String("admin"),
        }),
        ADMIN_ACCESS,
    ))
    // Rule: Members can read or list
    .rule(Rule::new(
        Effect::Allow,
        Target {
            principal: Matcher::Any,
            action: Matcher::OneOf(&["read", "list"]),
            resource: Matcher::Any,
        },
        Some(Condition::Equals {
            attr: "role",
            value: Value::String("member"),
        }),
        MEMBER_READ,
    ))
    .build()?;
```

And here is the same example using the DSL:

```rs
const ADMIN_ACCESS: ReasonCode = ReasonCode(100);
const MEMBER_READ: ReasonCode = ReasonCode(101);

// 1. Define the Policy
let policy = policy_builder![
    // Rule: Admins can do anything
    ALLOW ANY
        WHERE { role EQ "admin" } => ADMIN_ACCESS;

    // Rule: Members can read or list
    ALLOW { action: ["read", "list"] }
        WHERE { role EQ "member" } => MEMBER_READ;
]
.build()?;
```
