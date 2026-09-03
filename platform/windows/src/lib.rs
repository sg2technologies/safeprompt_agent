use tracing::info;

pub struct WindowsSystemProxy;

impl WindowsSystemProxy {
    pub fn enable_proxy(proxy_addr: &str) -> Result<(), String> {
        info!("Setting Windows System Proxy to {}", proxy_addr);
        Ok(())
    }

    pub fn disable_proxy() -> Result<(), String> {
        info!("Disabling Windows System Proxy");
        Ok(())
    }
}
