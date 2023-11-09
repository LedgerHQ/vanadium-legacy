
use core::{convert::TryInto, cmp::min};

use vanadium_sdk::{xrecv, xsend};
use alloc::{vec, vec::Vec};

use crate::error::AppError;

// xsend doesn't allow sending 0 bytes; therefore, we just send a
// a 1-byte acknowledgment when we don't have anything to send. 
const ACK: u8 = 0x42u8;

pub fn receive_message() -> Result<Vec<u8>, AppError> {
    let first_chunk = xrecv(256);
    
    // If we couldn't even read the length bytes, return an error
    if first_chunk.len() < 4 {
        return Err(AppError::new("Failed to read message length"));
    }

    let length = u32::from_be_bytes(first_chunk[0..4].try_into().expect("Cannot fail")) as usize;

    if first_chunk.len() > 4 + length {
        return Err(AppError::new("Too many bytes received on the first message"));
    }    

    // Accumulate the received data (escluding the length prefix) into the result vector.
    let mut result = first_chunk[4..].to_vec();

    // Calculate remaining bytes to read based on length field and the already read bytes
    let mut remaining_bytes = length - result.len();    
    while remaining_bytes > 0 {
        xsend(&vec![ACK]);
        let chunk = xrecv(256);
        if chunk.is_empty() {
            return Err(AppError::new("Failed to read entire message"));
        } else if chunk.len() > remaining_bytes {
            return Err(AppError::new("Too many bytes received"));
        }

        remaining_bytes -= chunk.len();
        result.extend(chunk);
    }

    // At this point, buffer contains the full message including the length field.
    Ok(result)
}

pub fn send_message(msg: &[u8]) -> Result<(), AppError> {
    // Encode the message length in big-endian format
    let length_be = (msg.len() as u32).to_be_bytes();

    let mut buffer = [0u8; 256];

    // Fill the buffer with the length prefix and as much of the message as fits
    buffer[..4].copy_from_slice(&length_be);
    
    let first_chunk_msg_bytes = min(256 - 4, msg.len());
    buffer[4..(4 + first_chunk_msg_bytes)].copy_from_slice(&msg[..first_chunk_msg_bytes]);
    
    // Send the initial buffer
    xsend(&buffer[..4 + first_chunk_msg_bytes]);

    let mut total_bytes_sent = first_chunk_msg_bytes;

    // Handle subsequent chunks
    while total_bytes_sent < msg.len() {
        let start_idx = total_bytes_sent;
        let end_idx = min(total_bytes_sent + 256, msg.len());

        let chunk_size = end_idx - start_idx;
        buffer[..chunk_size].copy_from_slice(&msg[start_idx..end_idx]);

        xrecv(256); // xrecv and xsend must always alternate
        xsend(&buffer[..chunk_size]);

        total_bytes_sent += chunk_size;
    }

    Ok(())
}
