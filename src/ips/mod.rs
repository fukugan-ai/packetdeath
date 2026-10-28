//! Stage 12: the IPS around the `eve.json` reader. `docs/design.md`
//! "段階12 IDS/IPS の業務水準化".

pub mod audit;
pub mod dropset;
pub mod engine;
pub mod escalate;
pub mod eve;
pub mod health;
pub mod never;
pub mod options;
pub mod parse;
pub mod policy;
pub mod report;
pub mod runtime;
pub mod testcmd;
