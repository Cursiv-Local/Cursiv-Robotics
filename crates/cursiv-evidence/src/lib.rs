//! Cursiv Robotics evidence core.
//!
//! Integrity (nothing changed), authenticity (a trusted key signed it),
//! scientific accuracy and sensor reliability are four separate questions.
//! This crate answers the first two cryptographically, checks plausibility
//! deterministically (`science`), and never claims the last two.

pub mod crypto;
pub mod legacy;
pub mod merkle;
pub mod model;
pub mod package;
pub mod reasoning;
pub mod science;
pub mod segment;
pub mod store;
pub mod trust;
pub mod units;
pub mod verify;
