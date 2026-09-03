pub struct CloudClient {
    pub api_base: String,
}

impl CloudClient {
    pub fn new(api_base: impl Into<String>) -> Self {
        Self {
            api_base: api_base.into(),
        }
    }

    pub fn send_heartbeat(&self) -> Result<(), String> {
        Ok(())
    }
}
