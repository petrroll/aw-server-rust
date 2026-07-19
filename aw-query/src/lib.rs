#[macro_use]
extern crate log;
extern crate serde;
extern crate serde_json;

use std::fmt;

use aw_models::TimeInterval;

use aw_datastore::Datastore;

pub mod datatype;

mod ast;
mod functions;
mod interpret;
mod lexer;
#[allow(
    clippy::match_single_binding,
    clippy::redundant_closure_call,
    unused_braces
)]
mod parser;

pub use crate::datatype::DataType;
pub use crate::interpret::VarEnv;

// TODO: add line numbers to errors
// (works during lexing, but not during parsing I believe)

#[derive(Debug)]
#[non_exhaustive]
pub enum QueryError {
    // Parser
    ParsingError(String),

    // Execution
    EmptyQuery(),
    VariableNotDefined(String),
    MathError(String),
    InvalidType(String),
    InvalidFunctionParameters(String),
    TimeIntervalError(String),
    BucketQueryError(String),
    DatastoreQueryError(String),
    RegexCompileError(String),
}

impl QueryError {
    pub fn kind(&self) -> &'static str {
        match self {
            QueryError::ParsingError(_) => "QueryParseException",
            QueryError::EmptyQuery() => "QueryInterpretException",
            QueryError::VariableNotDefined(_) => "QueryInterpretException",
            QueryError::MathError(_) => "QueryInterpretException",
            QueryError::InvalidType(_) => "QueryInterpretException",
            QueryError::InvalidFunctionParameters(_) => "QueryFunctionException",
            QueryError::TimeIntervalError(_) => "QueryFunctionException",
            QueryError::BucketQueryError(_) => "QueryFunctionException",
            QueryError::DatastoreQueryError(_) => "InternalServerError",
            QueryError::RegexCompileError(_) => "QueryFunctionException",
        }
    }

    pub fn is_server_error(&self) -> bool {
        matches!(self, QueryError::DatastoreQueryError(_))
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub fn query(code: &str, ti: &TimeInterval, ds: &Datastore) -> Result<DataType, QueryError> {
    let lexer = lexer::Lexer::new(code);
    let program = match parser::parse(lexer) {
        Ok(p) => p,
        Err(e) => {
            // TODO: Improve parsing error message
            warn!("ParsingError: {:?}", e);
            return Err(QueryError::ParsingError(format!("{e:?}")));
        }
    };
    interpret::interpret_prog(program, ti, ds)
}
