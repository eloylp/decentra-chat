use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors returned while converting system time into Unix timestamp seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum UnixTimestampError {
    #[error("system clock is before the Unix epoch")]
    BeforeUnixEpoch,
    #[error("Unix timestamp exceeds i64 range")]
    Overflow,
}

/// Return the current Unix timestamp in whole seconds.
pub(crate) fn unix_timestamp_secs() -> Result<i64, UnixTimestampError> {
    unix_timestamp_secs_at(SystemTime::now())
}

fn unix_timestamp_secs_at(time: SystemTime) -> Result<i64, UnixTimestampError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UnixTimestampError::BeforeUnixEpoch)?;
    duration_to_i64_secs(duration)
}

fn duration_to_i64_secs(duration: Duration) -> Result<i64, UnixTimestampError> {
    i64::try_from(duration.as_secs()).map_err(|_| UnixTimestampError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_timestamp_secs_at_epoch_is_zero() {
        assert_eq!(unix_timestamp_secs_at(UNIX_EPOCH), Ok(0));
    }

    #[test]
    fn unix_timestamp_secs_at_counts_whole_seconds_after_epoch() {
        assert_eq!(
            unix_timestamp_secs_at(UNIX_EPOCH + Duration::from_secs(42)),
            Ok(42)
        );
    }

    #[test]
    fn unix_timestamp_secs_at_rejects_times_before_epoch() {
        assert_eq!(
            unix_timestamp_secs_at(UNIX_EPOCH - Duration::from_secs(1)),
            Err(UnixTimestampError::BeforeUnixEpoch)
        );
    }

    #[test]
    fn duration_to_i64_secs_rejects_overflow() {
        assert_eq!(
            duration_to_i64_secs(Duration::from_secs(i64::MAX as u64 + 1)),
            Err(UnixTimestampError::Overflow)
        );
    }
}
