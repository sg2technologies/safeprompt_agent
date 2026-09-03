use tracing::info;

pub struct MacOsSystemProxy;

impl MacOsSystemProxy {
    pub fn enable_proxy(proxy_addr: &str) -> Result<(), String> {
        info!("Setting macOS System Proxy to {}", proxy_addr);
        Ok(())
    }

    pub fn disable_proxy() -> Result<(), String> {
        info!("Disabling macOS System Proxy");
        Ok(())
    }
}
