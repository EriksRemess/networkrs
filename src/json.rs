//! Minimal JSON value and renderer used only by the CLI binary.
//!
//! Keeping this module private lets the library expose typed Rust records
//! without imposing a serialization format or dependency. Numbers are stored
//! as already-formatted strings; callers must supply valid finite JSON numbers.

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    pub fn number(value: impl ToString) -> Self {
        Self::Number(value.to_string())
    }

    pub fn object(fields: impl IntoIterator<Item = (impl Into<String>, Value)>) -> Self {
        Self::Object(
            fields
                .into_iter()
                .map(|(name, value)| (name.into(), value))
                .collect(),
        )
    }

    pub fn render(&self) -> String {
        let mut output = String::new();
        self.write(&mut output);
        output
    }

    fn write(&self, output: &mut String) {
        match self {
            Self::Null => output.push_str("null"),
            Self::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) => output.push_str(value),
            Self::String(value) => write_string(output, value),
            Self::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    value.write(output);
                }
                output.push(']');
            }
            Self::Object(fields) => {
                output.push('{');
                for (index, (name, value)) in fields.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_string(output, name);
                    output.push(':');
                    value.write(output);
                }
                output.push('}');
            }
        }
    }
}

pub fn optional_string(value: Option<impl ToString>) -> Value {
    value
        .map(|value| Value::string(value.to_string()))
        .unwrap_or(Value::Null)
}

pub fn optional_number(value: Option<impl ToString>) -> Value {
    value.map(Value::number).unwrap_or(Value::Null)
}

pub fn strings(values: impl IntoIterator<Item = impl Into<String>>) -> Value {
    Value::Array(values.into_iter().map(Value::string).collect())
}

fn write_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_and_escapes_json() {
        let value = Value::object([
            ("text", Value::string("a\n\"b\\c")),
            ("enabled", Value::Bool(true)),
            ("missing", Value::Null),
            (
                "items",
                Value::Array(vec![Value::number(1), Value::number(2)]),
            ),
        ]);
        assert_eq!(
            value.render(),
            "{\"text\":\"a\\n\\\"b\\\\c\",\"enabled\":true,\"missing\":null,\"items\":[1,2]}"
        );
    }
}
