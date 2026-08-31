use crate::output;
use agent_dep_core::error::CoreResult;

pub async fn run(system: &str) -> CoreResult<()> {
    output::header(&format!("Deploying system: {system}"));
    output::warn("MVP-0: deploy is a stub. Real plan/apply lands in MVP-3+.");
    Ok(())
}
