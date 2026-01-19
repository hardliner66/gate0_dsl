#![feature(prelude_import)]
#[macro_use]
extern crate std;
#[prelude_import]
use std::prelude::rust_2024::*;
use gate0::{Policy, PolicyConfig, ReasonCode};
use gate0_dsl::policy_builder;
use insta::assert_debug_snapshot;
extern crate test;
#[rustc_test_marker = "test_simple_any_rules"]
#[doc(hidden)]
pub const test_simple_any_rules: test::TestDescAndFn = test::TestDescAndFn {
    desc: test::TestDesc {
        name: test::StaticTestName("test_simple_any_rules"),
        ignore: false,
        ignore_message: ::core::option::Option::None,
        source_file: "tests\\basic_test.rs",
        start_line: 7usize,
        start_col: 4usize,
        end_line: 7usize,
        end_col: 25usize,
        compile_fail: false,
        no_run: false,
        should_panic: test::ShouldPanic::No,
        test_type: test::TestType::IntegrationTest,
    },
    testfn: test::StaticTestFn(
        #[coverage(off)]
        || test::assert_test_result(test_simple_any_rules()),
    ),
};
fn test_simple_any_rules() {
    const REASON_ONE: ReasonCode = ReasonCode(1);
    const REASON_TWO: ReasonCode = ReasonCode(2);
    const REASON_THREE: ReasonCode = ReasonCode(3);
    let policy = {
        let mut builder = ::gate0::Policy::builder();
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target::any(),
                    None,
                    ::gate0::ReasonCode(1),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target::any(),
                    None,
                    REASON_ONE,
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target::any(),
                    None,
                    ::gate0::ReasonCode(2),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target::any(),
                    None,
                    REASON_TWO,
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Deny,
                    ::gate0::Target::any(),
                    None,
                    ::gate0::ReasonCode(3),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Deny,
                    ::gate0::Target::any(),
                    None,
                    REASON_THREE,
                ),
            );
        builder
    }
        .build()
        .unwrap();
    ::insta::_macro_support::assert_snapshot(
            (
                ::insta::_macro_support::AutoName,
                #[allow(clippy::redundant_closure_call)]
                (|v| ::alloc::__export::must_use({
                    ::alloc::fmt::format(format_args!("{0:#?}", v))
                }))(&policy)
                    .as_str(),
            )
                .into(),
            {
                use ::insta::_macro_support::{env, option_env};
                const WORKSPACE_ROOT: ::insta::_macro_support::Workspace = if let Some(
                    root,
                ) = ::core::option::Option::None::<&'static str> {
                    ::insta::_macro_support::Workspace::UseAsIs(root)
                } else {
                    ::insta::_macro_support::Workspace::DetectWithCargo(
                        "C:\\projects\\rust\\gate0_dsl",
                    )
                };
                ::insta::_macro_support::get_cargo_workspace(WORKSPACE_ROOT)
            }
                .as_path(),
            {
                fn f() {}
                fn type_name_of_val<T>(_: T) -> &'static str {
                    ::insta::_macro_support::any::type_name::<T>()
                }
                let mut name = type_name_of_val(f).strip_suffix("::f").unwrap_or("");
                while let Some(rest) = name.strip_suffix("::{{closure}}") {
                    name = rest;
                }
                name
            },
            "basic_test",
            "tests\\basic_test.rs",
            24u32,
            "policy",
        )
        .unwrap();
}
extern crate test;
#[rustc_test_marker = "test_simple_tuple_rules"]
#[doc(hidden)]
pub const test_simple_tuple_rules: test::TestDescAndFn = test::TestDescAndFn {
    desc: test::TestDesc {
        name: test::StaticTestName("test_simple_tuple_rules"),
        ignore: false,
        ignore_message: ::core::option::Option::None,
        source_file: "tests\\basic_test.rs",
        start_line: 28usize,
        start_col: 4usize,
        end_line: 28usize,
        end_col: 27usize,
        compile_fail: false,
        no_run: false,
        should_panic: test::ShouldPanic::No,
        test_type: test::TestType::IntegrationTest,
    },
    testfn: test::StaticTestFn(
        #[coverage(off)]
        || test::assert_test_result(test_simple_tuple_rules()),
    ),
};
fn test_simple_tuple_rules() {
    const REASON_ONE: ReasonCode = ReasonCode(1);
    const REASON_TWO: ReasonCode = ReasonCode(2);
    let policy = {
        let mut builder = ::gate0::Policy::builder();
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::Exact("alice"),
                        action: ::gate0::Matcher::Exact("read"),
                        resource: ::gate0::Matcher::Exact("doc1"),
                    },
                    None,
                    ::gate0::ReasonCode(1),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::Exact("bob"),
                        action: ::gate0::Matcher::Exact("write"),
                        resource: ::gate0::Matcher::Exact("doc2"),
                    },
                    None,
                    REASON_ONE,
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Deny,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::Exact("eve"),
                        action: ::gate0::Matcher::Any,
                        resource: ::gate0::Matcher::Any,
                    },
                    None,
                    ::gate0::ReasonCode(2),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Deny,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::OneOf(&["eve", "carl"]),
                        action: ::gate0::Matcher::Exact("write"),
                        resource: ::gate0::Matcher::Any,
                    },
                    None,
                    ::gate0::ReasonCode(2),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Deny,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::Exact("mallory"),
                        action: ::gate0::Matcher::Exact("delete"),
                        resource: ::gate0::Matcher::Exact("doc3"),
                    },
                    None,
                    REASON_TWO,
                ),
            );
        builder
    }
        .build()
        .unwrap();
    ::insta::_macro_support::assert_snapshot(
            (
                ::insta::_macro_support::AutoName,
                #[allow(clippy::redundant_closure_call)]
                (|v| ::alloc::__export::must_use({
                    ::alloc::fmt::format(format_args!("{0:#?}", v))
                }))(&policy)
                    .as_str(),
            )
                .into(),
            {
                use ::insta::_macro_support::{env, option_env};
                const WORKSPACE_ROOT: ::insta::_macro_support::Workspace = if let Some(
                    root,
                ) = ::core::option::Option::None::<&'static str> {
                    ::insta::_macro_support::Workspace::UseAsIs(root)
                } else {
                    ::insta::_macro_support::Workspace::DetectWithCargo(
                        "C:\\projects\\rust\\gate0_dsl",
                    )
                };
                ::insta::_macro_support::get_cargo_workspace(WORKSPACE_ROOT)
            }
                .as_path(),
            {
                fn f() {}
                fn type_name_of_val<T>(_: T) -> &'static str {
                    ::insta::_macro_support::any::type_name::<T>()
                }
                let mut name = type_name_of_val(f).strip_suffix("::f").unwrap_or("");
                while let Some(rest) = name.strip_suffix("::{{closure}}") {
                    name = rest;
                }
                name
            },
            "basic_test",
            "tests\\basic_test.rs",
            42u32,
            "policy",
        )
        .unwrap();
}
extern crate test;
#[rustc_test_marker = "test_field_rules"]
#[doc(hidden)]
pub const test_field_rules: test::TestDescAndFn = test::TestDescAndFn {
    desc: test::TestDesc {
        name: test::StaticTestName("test_field_rules"),
        ignore: false,
        ignore_message: ::core::option::Option::None,
        source_file: "tests\\basic_test.rs",
        start_line: 46usize,
        start_col: 4usize,
        end_line: 46usize,
        end_col: 20usize,
        compile_fail: false,
        no_run: false,
        should_panic: test::ShouldPanic::No,
        test_type: test::TestType::IntegrationTest,
    },
    testfn: test::StaticTestFn(
        #[coverage(off)]
        || test::assert_test_result(test_field_rules()),
    ),
};
fn test_field_rules() {
    const REASON_ONE: ReasonCode = ReasonCode(1);
    const REASON_TWO: ReasonCode = ReasonCode(2);
    let policy = {
        let mut builder = ::gate0::Policy::builder();
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::Exact("alice"),
                        action: ::gate0::Matcher::Exact("read"),
                        resource: ::gate0::Matcher::Exact("doc1"),
                    },
                    None,
                    ::gate0::ReasonCode(1),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::OneOf(&["bob", "carl"]),
                        action: ::gate0::Matcher::OneOf(&["write", "update"]),
                        resource: ::gate0::Matcher::Any,
                    },
                    None,
                    REASON_ONE,
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Deny,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::Exact("eve"),
                        action: ::gate0::Matcher::Any,
                        resource: ::gate0::Matcher::Any,
                    },
                    None,
                    ::gate0::ReasonCode(2),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Deny,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::OneOf(&["mallory", "trent"]),
                        action: ::gate0::Matcher::Exact("delete"),
                        resource: ::gate0::Matcher::OneOf(&["doc2", "doc3"]),
                    },
                    None,
                    REASON_TWO,
                ),
            );
        builder
    }
        .build()
        .unwrap();
    ::insta::_macro_support::assert_snapshot(
            (
                ::insta::_macro_support::AutoName,
                #[allow(clippy::redundant_closure_call)]
                (|v| ::alloc::__export::must_use({
                    ::alloc::fmt::format(format_args!("{0:#?}", v))
                }))(&policy)
                    .as_str(),
            )
                .into(),
            {
                use ::insta::_macro_support::{env, option_env};
                const WORKSPACE_ROOT: ::insta::_macro_support::Workspace = if let Some(
                    root,
                ) = ::core::option::Option::None::<&'static str> {
                    ::insta::_macro_support::Workspace::UseAsIs(root)
                } else {
                    ::insta::_macro_support::Workspace::DetectWithCargo(
                        "C:\\projects\\rust\\gate0_dsl",
                    )
                };
                ::insta::_macro_support::get_cargo_workspace(WORKSPACE_ROOT)
            }
                .as_path(),
            {
                fn f() {}
                fn type_name_of_val<T>(_: T) -> &'static str {
                    ::insta::_macro_support::any::type_name::<T>()
                }
                let mut name = type_name_of_val(f).strip_suffix("::f").unwrap_or("");
                while let Some(rest) = name.strip_suffix("::{{closure}}") {
                    name = rest;
                }
                name
            },
            "basic_test",
            "tests\\basic_test.rs",
            77u32,
            "policy",
        )
        .unwrap();
}
extern crate test;
#[rustc_test_marker = "test_mixed_rules"]
#[doc(hidden)]
pub const test_mixed_rules: test::TestDescAndFn = test::TestDescAndFn {
    desc: test::TestDesc {
        name: test::StaticTestName("test_mixed_rules"),
        ignore: false,
        ignore_message: ::core::option::Option::None,
        source_file: "tests\\basic_test.rs",
        start_line: 81usize,
        start_col: 4usize,
        end_line: 81usize,
        end_col: 20usize,
        compile_fail: false,
        no_run: false,
        should_panic: test::ShouldPanic::No,
        test_type: test::TestType::IntegrationTest,
    },
    testfn: test::StaticTestFn(
        #[coverage(off)]
        || test::assert_test_result(test_mixed_rules()),
    ),
};
fn test_mixed_rules() {
    const REASON_TWO: ReasonCode = ReasonCode(2);
    const REASON_THREE: ReasonCode = ReasonCode(3);
    let policy = {
        let mut builder = ::gate0::Policy::builder();
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target::any(),
                    None,
                    ::gate0::ReasonCode(1),
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Allow,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::Exact("alice"),
                        action: ::gate0::Matcher::Exact("read"),
                        resource: ::gate0::Matcher::Exact("doc1"),
                    },
                    None,
                    REASON_TWO,
                ),
            );
        builder = builder
            .rule(
                ::gate0::Rule::new(
                    ::gate0::Effect::Deny,
                    ::gate0::Target {
                        principal: ::gate0::Matcher::Exact("eve"),
                        action: ::gate0::Matcher::Any,
                        resource: ::gate0::Matcher::Any,
                    },
                    None,
                    REASON_THREE,
                ),
            );
        builder
    }
        .build()
        .unwrap();
    ::insta::_macro_support::assert_snapshot(
            (
                ::insta::_macro_support::AutoName,
                #[allow(clippy::redundant_closure_call)]
                (|v| ::alloc::__export::must_use({
                    ::alloc::fmt::format(format_args!("{0:#?}", v))
                }))(&policy)
                    .as_str(),
            )
                .into(),
            {
                use ::insta::_macro_support::{env, option_env};
                const WORKSPACE_ROOT: ::insta::_macro_support::Workspace = if let Some(
                    root,
                ) = ::core::option::Option::None::<&'static str> {
                    ::insta::_macro_support::Workspace::UseAsIs(root)
                } else {
                    ::insta::_macro_support::Workspace::DetectWithCargo(
                        "C:\\projects\\rust\\gate0_dsl",
                    )
                };
                ::insta::_macro_support::get_cargo_workspace(WORKSPACE_ROOT)
            }
                .as_path(),
            {
                fn f() {}
                fn type_name_of_val<T>(_: T) -> &'static str {
                    ::insta::_macro_support::any::type_name::<T>()
                }
                let mut name = type_name_of_val(f).strip_suffix("::f").unwrap_or("");
                while let Some(rest) = name.strip_suffix("::{{closure}}") {
                    name = rest;
                }
                name
            },
            "basic_test",
            "tests\\basic_test.rs",
            96u32,
            "policy",
        )
        .unwrap();
}
extern crate test;
#[rustc_test_marker = "test_config"]
#[doc(hidden)]
pub const test_config: test::TestDescAndFn = test::TestDescAndFn {
    desc: test::TestDesc {
        name: test::StaticTestName("test_config"),
        ignore: false,
        ignore_message: ::core::option::Option::None,
        source_file: "tests\\basic_test.rs",
        start_line: 100usize,
        start_col: 4usize,
        end_line: 100usize,
        end_col: 15usize,
        compile_fail: false,
        no_run: false,
        should_panic: test::ShouldPanic::No,
        test_type: test::TestType::IntegrationTest,
    },
    testfn: test::StaticTestFn(
        #[coverage(off)]
        || test::assert_test_result(test_config()),
    ),
};
fn test_config() {
    let policy = {
        let mut builder = ::gate0::Policy::builder();
        builder = builder
            .config(::gate0::PolicyConfig {
                max_rules: 500,
                max_condition_depth: 5,
                ..::gate0::PolicyConfig::default()
            });
        builder
    }
        .build()
        .unwrap();
    match (&policy.config().max_rules, &500) {
        (left_val, right_val) => {
            if !(*left_val == *right_val) {
                let kind = ::core::panicking::AssertKind::Eq;
                ::core::panicking::assert_failed(
                    kind,
                    &*left_val,
                    &*right_val,
                    ::core::option::Option::None,
                );
            }
        }
    };
    match (&policy.config().max_condition_depth, &5) {
        (left_val, right_val) => {
            if !(*left_val == *right_val) {
                let kind = ::core::panicking::AssertKind::Eq;
                ::core::panicking::assert_failed(
                    kind,
                    &*left_val,
                    &*right_val,
                    ::core::option::Option::None,
                );
            }
        }
    };
}
extern crate test;
#[rustc_test_marker = "test_where"]
#[doc(hidden)]
pub const test_where: test::TestDescAndFn = test::TestDescAndFn {
    desc: test::TestDesc {
        name: test::StaticTestName("test_where"),
        ignore: false,
        ignore_message: ::core::option::Option::None,
        source_file: "tests\\basic_test.rs",
        start_line: 115usize,
        start_col: 4usize,
        end_line: 115usize,
        end_col: 14usize,
        compile_fail: false,
        no_run: false,
        should_panic: test::ShouldPanic::No,
        test_type: test::TestType::IntegrationTest,
    },
    testfn: test::StaticTestFn(
        #[coverage(off)]
        || test::assert_test_result(test_where()),
    ),
};
fn test_where() {
    let policy = (/*ERROR*/).build().unwrap();
    ::insta::_macro_support::assert_snapshot(
            (
                ::insta::_macro_support::AutoName,
                #[allow(clippy::redundant_closure_call)]
                (|v| ::alloc::__export::must_use({
                    ::alloc::fmt::format(format_args!("{0:#?}", v))
                }))(&policy)
                    .as_str(),
            )
                .into(),
            {
                use ::insta::_macro_support::{env, option_env};
                const WORKSPACE_ROOT: ::insta::_macro_support::Workspace = if let Some(
                    root,
                ) = ::core::option::Option::None::<&'static str> {
                    ::insta::_macro_support::Workspace::UseAsIs(root)
                } else {
                    ::insta::_macro_support::Workspace::DetectWithCargo(
                        "C:\\projects\\rust\\gate0_dsl",
                    )
                };
                ::insta::_macro_support::get_cargo_workspace(WORKSPACE_ROOT)
            }
                .as_path(),
            {
                fn f() {}
                fn type_name_of_val<T>(_: T) -> &'static str {
                    ::insta::_macro_support::any::type_name::<T>()
                }
                let mut name = type_name_of_val(f).strip_suffix("::f").unwrap_or("");
                while let Some(rest) = name.strip_suffix("::{{closure}}") {
                    name = rest;
                }
                name
            },
            "basic_test",
            "tests\\basic_test.rs",
            129u32,
            "policy",
        )
        .unwrap();
}
extern crate test;
#[rustc_test_marker = "test_external_builder"]
#[doc(hidden)]
pub const test_external_builder: test::TestDescAndFn = test::TestDescAndFn {
    desc: test::TestDesc {
        name: test::StaticTestName("test_external_builder"),
        ignore: false,
        ignore_message: ::core::option::Option::None,
        source_file: "tests\\basic_test.rs",
        start_line: 133usize,
        start_col: 4usize,
        end_line: 133usize,
        end_col: 25usize,
        compile_fail: false,
        no_run: false,
        should_panic: test::ShouldPanic::No,
        test_type: test::TestType::IntegrationTest,
    },
    testfn: test::StaticTestFn(
        #[coverage(off)]
        || test::assert_test_result(test_external_builder()),
    ),
};
fn test_external_builder() {
    let builder = Policy::builder()
        .config(PolicyConfig {
            max_rules: 200,
            ..PolicyConfig::default()
        });
    let policy = {
        let mut builder = builder;
        builder
    }
        .build()
        .unwrap();
    ::insta::_macro_support::assert_snapshot(
            (
                ::insta::_macro_support::AutoName,
                #[allow(clippy::redundant_closure_call)]
                (|v| ::alloc::__export::must_use({
                    ::alloc::fmt::format(format_args!("{0:#?}", v))
                }))(&policy)
                    .as_str(),
            )
                .into(),
            {
                use ::insta::_macro_support::{env, option_env};
                const WORKSPACE_ROOT: ::insta::_macro_support::Workspace = if let Some(
                    root,
                ) = ::core::option::Option::None::<&'static str> {
                    ::insta::_macro_support::Workspace::UseAsIs(root)
                } else {
                    ::insta::_macro_support::Workspace::DetectWithCargo(
                        "C:\\projects\\rust\\gate0_dsl",
                    )
                };
                ::insta::_macro_support::get_cargo_workspace(WORKSPACE_ROOT)
            }
                .as_path(),
            {
                fn f() {}
                fn type_name_of_val<T>(_: T) -> &'static str {
                    ::insta::_macro_support::any::type_name::<T>()
                }
                let mut name = type_name_of_val(f).strip_suffix("::f").unwrap_or("");
                while let Some(rest) = name.strip_suffix("::{{closure}}") {
                    name = rest;
                }
                name
            },
            "basic_test",
            "tests\\basic_test.rs",
            143u32,
            "policy",
        )
        .unwrap();
}
#[rustc_main]
#[coverage(off)]
#[doc(hidden)]
pub fn main() -> () {
    extern crate test;
    test::test_main_static(
        &[
            &test_config,
            &test_external_builder,
            &test_field_rules,
            &test_mixed_rules,
            &test_simple_any_rules,
            &test_simple_tuple_rules,
            &test_where,
        ],
    )
}
