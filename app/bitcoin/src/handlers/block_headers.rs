use alloc::borrow::Cow;

use bitcoin::block::Header;
use error::*;

use crate::{message::message::{RequestGetLatestBlockHeader, ResponseGetLatestBlockHeader, RequestSetLatestBlockHeader, ResponseSetLatestBlockHeader}, state::AppState};

use bitcoin::consensus::encode::Decodable;

pub fn handle_get_latest_block_header<'a>(req: RequestGetLatestBlockHeader, app_state: &mut AppState) -> Result<ResponseGetLatestBlockHeader<'a>> {
    Ok(ResponseGetLatestBlockHeader { 
        height: app_state.current_block_height,
        block_hash: Cow::Owned(app_state.current_block_hash.to_vec()),
        block_header: Cow::Owned(app_state.current_block_header.to_vec())
    })
}

pub fn handle_set_latest_block_header(req: RequestSetLatestBlockHeader, app_state: &mut AppState) -> Result<ResponseSetLatestBlockHeader> {
    if app_state.current_block_height + 1 != req.height {
        return Err(AppError::new("Cannot skip blocks"))
    }

    let mut data_slice = &*req.block_header;
    let header = Header::consensus_decode(&mut data_slice)
        .map_err(|_| AppError::new("Failed to decode block header"))?;

    header.validate_pow(header.target())
        .map_err(|_| AppError::new("Invalid Proof of Work"))?;

    // TODO: what else do we need to check?
    // I suppose: difficulty adjustment

    app_state.current_block_height = req.height;
    app_state.current_block_hash.copy_from_slice(&req.block_hash);
    app_state.current_block_header.copy_from_slice(&req.block_header);

    Ok(ResponseSetLatestBlockHeader {})
}
