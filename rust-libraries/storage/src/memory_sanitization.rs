// Memory sanitization and secure zeroization

use std::sync::atomic::{compiler_fence, Ordering};

/// Zeroize buffer (prevents compiler optimization)
pub fn zeroize_buffer(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Zeroize stack frame
pub fn zeroize_stack() {
    // TODO: Implement stack zeroization
}

/// Secure free (zeroize before deallocation)
pub fn secure_free(mut data: Vec<u8>) {
    zeroize_buffer(&mut data);
    drop(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize() {
        let mut buffer = vec![1, 2, 3, 4, 5];
        zeroize_buffer(&mut buffer);
        
        assert_eq!(buffer, vec![0, 0, 0, 0, 0]);
    }
}
