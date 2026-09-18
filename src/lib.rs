#![forbid(unsafe_code)]

//! Authenticate by bearer token: an opaque token against a token store, with
//! its expiry.
//!
//! RFC 6750 carries a token in `Authorization: Bearer <token>` and whoever
//! bears it is taken for whoever it was issued to: possession, and nothing
//! else. The first gate calls the first eight characters of the token the
//! claim — enough for the record to tell two tokens apart without holding
//! either — and lets the token ride on `Presented::proof` under
//! `bearer.token`. This gate hashes the token, compares it with every token
//! it holds in constant time, checks that the claim is that token's short
//! form or the name it was issued under, and then reads the expiry.
//!
//! Opaque only. A token with an issuer's signature on it is `jwt`, one an
//! authorization server vouches for is `oauth2`, and both are other gates'.
//! An expired token is refused saying so; an unknown one is refused without
//! saying what the store holds.

pub mod store;

pub use store::{Token, TokenStore};

use authenticate::store::sha256;
use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use std::time::{SystemTime, UNIX_EPOCH};
use xcore::{Mechanism, mechanism};

/// The proof name this verifier reads off a `Presented`: the whole token.
pub const PROOF: &str = "bearer.token";

/// How many characters of a token the first gate puts on the claim.
pub const SHORT_FORM: usize = 8;

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Seconds since the Unix epoch, now.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The form of a token that may reach the record: its first eight
/// characters and an ellipsis, as the first gate writes it.
#[must_use]
pub fn short_form(token: &str) -> String {
    token
        .chars()
        .take(SHORT_FORM)
        .chain(std::iter::once('…'))
        .collect()
}

/// Verifies a `bearer` claim with a `bearer.token` proof against a store.
pub struct BearerAuthenticator {
    store: TokenStore,
    clock: Clock,
}

impl BearerAuthenticator {
    #[must_use]
    pub fn new(store: TokenStore) -> Self {
        Self {
            store,
            clock: Box::new(now),
        }
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// The tokens this verifies against.
    #[must_use]
    pub fn store(&self) -> &TokenStore {
        &self.store
    }
}

impl Authenticator for BearerAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::bearer()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies bearer"
            )));
        }
        let token = presented.proof(PROOF).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{PROOF}' proof was presented with the claim '{}'",
                presented.value
            ))
        })?;
        if token.is_empty() {
            return Err(AuthenticateError::new(
                "the bearer token presented is empty",
            ));
        }
        let Some(held) = self.store.holding(&sha256(token.as_bytes())) else {
            return Ok(Verified::Refused);
        };
        if presented.value != short_form(token) && presented.value != held.name() {
            return Err(AuthenticateError::new(format!(
                "the claim names '{}' and the token presented is another",
                presented.value
            )));
        }
        let now = (self.clock)();
        if let Some(expiry) = held.expiry()
            && now >= expiry
        {
            return Err(AuthenticateError::new(format!(
                "the token issued to '{}' expired at {expiry} and it is {now}",
                held.name()
            )));
        }
        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::{Acceptance, PartyRegistry, Refusal, authenticate};
    use xcore::{PartyId, Purpose};

    const NOW: i64 = 1_800_000_000;
    const TOKEN: &str = "mF_9.B5f-4.1JqM";

    fn verifier() -> BearerAuthenticator {
        let mut store = TokenStore::new();
        store.insert("partner-x", TOKEN, Some(NOW + 3600));
        store.insert("partner-z", "zzzz-expired-token", Some(NOW - 1));
        BearerAuthenticator::new(store).with_clock(|| NOW)
    }

    fn claim(token: &str) -> Presented {
        Presented::passed(mechanism::bearer(), short_form(token)).with_proof(PROOF, token)
    }

    #[test]
    fn a_token_the_store_holds_proves_the_claim() {
        let verifier = verifier();
        let presented = claim(TOKEN);
        assert_eq!(presented.value, "mF_9.B5f…");
        assert_eq!(
            verifier.verify(&presented).expect("verified"),
            Verified::Proven
        );
        // A claim under the name the token was issued to reads too.
        let named = Presented::passed(mechanism::bearer(), "partner-x").with_proof(PROOF, TOKEN);
        assert_eq!(verifier.verify(&named).expect("verified"), Verified::Proven);
    }

    #[test]
    fn a_token_the_store_does_not_hold_is_refused() {
        assert_eq!(
            verifier()
                .verify(&claim("mF_9.B5f-4.1JqN"))
                .expect("verified"),
            Verified::Refused
        );
    }

    #[test]
    fn an_expired_token_is_refused_saying_when_it_expired() {
        let failure = verifier()
            .verify(&claim("zzzz-expired-token"))
            .expect_err("refused");
        assert_eq!(
            failure.message,
            format!(
                "the token issued to 'partner-z' expired at {} and it is {NOW}",
                NOW - 1
            )
        );
    }

    #[test]
    fn a_claim_that_is_not_the_presented_token_is_refused() {
        let crossed = Presented::passed(mechanism::bearer(), short_form("zzzz-expired-token"))
            .with_proof(PROOF, TOKEN);
        let failure = verifier().verify(&crossed).expect_err("refused");
        assert!(
            failure.message.contains("the token presented is another"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn a_missing_proof_and_another_mechanism_are_refused_by_name() {
        let bare = Presented::passed(mechanism::bearer(), "mF_9.B5f…");
        let failure = verifier().verify(&bare).expect_err("refused");
        assert!(
            failure.message.contains("'bearer.token' proof"),
            "{}",
            failure.message
        );

        let jwt = Presented::passed(mechanism::jwt(), "alice").with_proof("jwt.token", "a.b.c");
        let failure = verifier().verify(&jwt).expect_err("refused");
        assert!(failure.message.contains("'jwt'"), "{}", failure.message);
    }

    struct Registry;

    impl PartyRegistry for Registry {
        fn resolve(&self, mechanism: &str, _purpose: Purpose, value: &str) -> Option<PartyId> {
            (mechanism == "bearer" && value == "mF_9.B5f…").then(|| PartyId::new(5))
        }
    }

    #[test]
    fn through_the_gate_the_token_stays_off_the_record() {
        let verifier = verifier();
        let acceptance = Acceptance::closed().accepting(&mechanism::bearer());
        let presented = claim(TOKEN);
        assert!(!format!("{presented:?}").contains(TOKEN));

        let identity =
            authenticate(&acceptance, &[&verifier], &Registry, &presented).expect("accepted");
        assert_eq!(identity.party_id, Some(PartyId::new(5)));
        assert_eq!(identity.value, "mF_9.B5f…");

        let refusal = authenticate(
            &acceptance,
            &[&verifier],
            &Registry,
            &claim("unknown-token"),
        )
        .expect_err("refused");
        assert_eq!(
            refusal,
            Refusal::NotProven {
                mechanism: "bearer".to_string(),
                detail: "the claim did not hold".to_string()
            }
        );
    }
}
