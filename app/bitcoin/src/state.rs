// state that is persisted in RAM across requests of the app

use std::collections::HashMap;

use schnorr_fun::musig::NonceKeyPair;

#[derive(Debug)]
pub struct MusigSession {
    pub nonce_keypair: NonceKeyPair
}

#[derive(Debug)]
pub struct AppState {
    pub musig_sessions: HashMap<Vec<u8>, MusigSession>
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            musig_sessions: HashMap::new()
        }
    }
}
