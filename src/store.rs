//! The token store: opaque bearer tokens hashed at rest, each with the name
//! it was issued under and its expiry.
//!
//! RFC 6750 is carriage and says nothing of what a token is; an opaque one
//! is a secret the node, or something the node trusts, minted and wrote
//! down. What is written down is SHA-256 of the token, the name it was
//! issued under and the first second at which it is no longer good. A
//! lookup compares the presented hash with every hash held, each in
//! constant time and with no early exit.

use authenticate::store::{KEY_LENGTH, constant_time_eq, sha256};

/// One token as the store holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    name: String,
    hash: [u8; KEY_LENGTH],
    expiry: Option<i64>,
}

impl Token {
    /// The name the token was issued under; never the token.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// SHA-256 of the token.
    #[must_use]
    pub const fn hash(&self) -> &[u8; KEY_LENGTH] {
        &self.hash
    }

    /// The first second, since the Unix epoch, at which the token is no
    /// longer good. `None` is a token that does not expire.
    #[must_use]
    pub const fn expiry(&self) -> Option<i64> {
        self.expiry
    }
}

/// The tokens a node takes, built from configuration and read-only after.
#[derive(Clone, Debug, Default)]
pub struct TokenStore {
    tokens: Vec<Token>,
}

impl TokenStore {
    /// A store holding nothing, which verifies nobody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `token` under `name`, hashed. The token is not kept.
    pub fn insert(&mut self, name: &str, token: &str, expiry: Option<i64>) {
        self.insert_hash(name, sha256(token.as_bytes()), expiry);
    }

    /// Hold a token hashed elsewhere, as configuration carries it.
    pub fn insert_hash(&mut self, name: &str, hash: [u8; KEY_LENGTH], expiry: Option<i64>) {
        self.tokens.push(Token {
            name: name.to_string(),
            hash,
            expiry,
        });
    }

    /// How many tokens are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// The token whose hash is `hash`, compared in constant time against
    /// every token held.
    #[must_use]
    pub fn holding(&self, hash: &[u8; KEY_LENGTH]) -> Option<&Token> {
        self.tokens.iter().fold(None, |found, token| {
            if constant_time_eq(&token.hash, hash) {
                found.or(Some(token))
            } else {
                found
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_found_by_its_hash_and_the_token_itself_is_not_kept() {
        let mut store = TokenStore::new();
        assert!(store.is_empty());
        store.insert("partner-x", "mF_9.B5f-4.1JqM", Some(42));
        let held = store.holding(&sha256(b"mF_9.B5f-4.1JqM")).expect("held");
        assert_eq!(held.name(), "partner-x");
        assert_eq!(held.expiry(), Some(42));
        assert_eq!(store.len(), 1);
        assert!(!format!("{store:?}").contains("mF_9.B5f-4.1JqM"));
    }

    #[test]
    fn a_token_hashed_elsewhere_is_found_and_another_is_not() {
        let mut store = TokenStore::new();
        store.insert_hash("partner-y", sha256(b"opaque"), None);
        assert_eq!(
            store.holding(&sha256(b"opaque")).map(Token::name),
            Some("partner-y")
        );
        assert!(store.holding(&sha256(b"opaque ")).is_none());
    }
}
