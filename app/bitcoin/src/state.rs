#[derive(Debug)]
pub struct AppState {
    pub current_block_height: u32,
    pub current_block_hash: [u8; 32],
    pub current_block_header: [u8; 80],
}
