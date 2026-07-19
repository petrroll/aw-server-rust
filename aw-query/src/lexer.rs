use plex::lexer;

#[derive(Debug, Clone)]
pub enum Token {
    Ident(String),

    If,
    ElseIf,
    Else,
    Return,

    Bool(bool),
    Null,
    Number(f64),
    String(String),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Equals,
    Assign,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Semi,

    Whitespace,
    Newline,
    Comment,
}

fn number_token(text: &str) -> Token {
    match text.parse() {
        Ok(number) => Token::Number(number),
        Err(error) => panic!("Number {text} is out of range: {error}"),
    }
}

fn string_token(text: &str) -> Token {
    let value = &text[1..text.len() - 1];
    let mut decoded = String::new();
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let mut count = 1;
        while chars.peek() == Some(&'\\') {
            chars.next();
            count += 1;
        }
        if chars.peek() == Some(&'"') && count % 2 == 1 {
            for _ in 0..((count - 1) / 2) {
                decoded.push('\\');
            }
            decoded.push(chars.next().unwrap());
        } else {
            for _ in 0..count {
                decoded.push('\\');
            }
        }
    }
    Token::String(decoded)
}

lexer! {
    fn next_token(text: 'a) -> (Token, &'a str);

    r#"[ \t\r]+"# => (Token::Whitespace, text),
    r#"\n"# => (Token::Newline, text),
    // Python-style comments (# ...)
    r#"#[^\n]*"# => (Token::Comment, text),

    r#"if"# => (Token::If, text),
    r#"elif"# => (Token::ElseIf, text),
    r#"else"# => (Token::Else, text),
    r#"return"# => (Token::Return, text),

    r#"true"# => (Token::Bool(true), text),
    r#"false"# => (Token::Bool(false), text),
    // TODO: Deprecate/Remove?
    r#"True"# => (Token::Bool(true), text),
    r#"False"# => (Token::Bool(false), text),
    r#"null"# => (Token::Null, text),
    r#"None"# => (Token::Null, text),

    r#"\"([^\"\\]|\\.)*\""# => (string_token(text), text),
    r#"[0-9]+\.[0-9]+[eE]\+[0-9]+"# => (number_token(text), text),
    r#"[0-9]+\.[0-9]+[eE]-[0-9]+"# => (number_token(text), text),
    r#"[0-9]+\.[0-9]+[eE][0-9]+"# => (number_token(text), text),
    r#"[0-9]+[eE]\+[0-9]+"# => (number_token(text), text),
    r#"[0-9]+[eE]-[0-9]+"# => (number_token(text), text),
    r#"[0-9]+[eE][0-9]+"# => (number_token(text), text),
    r#"[0-9]+\.[0-9]+"# => (number_token(text), text),
    r#"[0-9]+"# => (number_token(text), text),

    r#"[a-zA-Z_][a-zA-Z0-9_]*"# => (Token::Ident(text.to_owned()), text),

    r#"=="# => (Token::Equals, text),
    r#"="# => (Token::Assign, text),
    r#"\+"# => (Token::Plus, text),
    r#"-"# => (Token::Minus, text),
    r#"\*"# => (Token::Star, text),
    r#"/"# => (Token::Slash, text),
    r#"%"# => (Token::Percent, text),
    r#"\("# => (Token::LParen, text),
    r#"\)"# => (Token::RParen, text),
    r#"\["# => (Token::LBracket, text),
    r#"\]"# => (Token::RBracket, text),
    r#"\{"# => (Token::LBrace, text),
    r#"\}"# => (Token::RBrace, text),
    r#","# => (Token::Comma, text),
    r#":"# => (Token::Colon, text),
    r#";"# => (Token::Semi, text),
}

pub struct Lexer<'a> {
    original: &'a str,
    remaining: &'a str,
    line: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(s: &'a str) -> Lexer<'a> {
        Lexer {
            original: s,
            remaining: s,
            line: 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Span {
    pub lo: usize,
    pub hi: usize,
    pub line: usize,
}

fn span_in(s: &str, t: &str, l: usize) -> Span {
    let lo = s.as_ptr() as usize - t.as_ptr() as usize;
    Span {
        lo,
        hi: lo + s.len(),
        line: l,
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = (Token, Span);
    fn next(&mut self) -> Option<(Token, Span)> {
        loop {
            let tok = if let Some((tok, new_remaining)) = next_token(self.remaining) {
                self.remaining = new_remaining;
                tok
            } else {
                return None;
            };
            match tok {
                (Token::Whitespace, _) | (Token::Comment, _) => {
                    continue;
                }
                (Token::Newline, _) => {
                    self.line += 1;
                    continue;
                }
                (tok, span) => {
                    return Some((tok, span_in(span, self.original, self.line)));
                }
            }
        }
    }
}
