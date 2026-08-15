use std::io;

pub fn fill_random(output: &mut [u8]) -> io::Result<()> {
    platform::fill_random(output)
}

#[cfg(unix)]
mod platform {
    use std::{
        fs::File,
        io::{self, Read},
    };

    const RANDOM_DEVICE: &str = "/dev/urandom";

    pub(super) fn fill_random(output: &mut [u8]) -> io::Result<()> {
        if output.is_empty() {
            return Ok(());
        }

        let mut source = File::open(RANDOM_DEVICE)?;

        source.read_exact(output)
    }
}

#[cfg(not(unix))]
mod platform {
    use std::io;

    pub(super) fn fill_random(_: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure OS randomness is not implemented for this platform yet",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::fill_random;

    #[test]
    fn fills_random_bytes_from_operating_system() {
        let mut output = [0_u8; 64];

        fill_random(&mut output).unwrap();

        assert!(
            output.iter().any(|byte| *byte != 0),
            "OS random source unexpectedly returned an all-zero buffer"
        );
    }

    #[test]
    fn consecutive_random_samples_differ() {
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];

        fill_random(&mut first).unwrap();
        fill_random(&mut second).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn accepts_empty_output_buffer() {
        let mut output = [];

        fill_random(&mut output).unwrap();
    }
}
