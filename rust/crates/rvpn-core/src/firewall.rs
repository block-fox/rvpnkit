//! Windows Firewall helpers for explicit IP block rules.

use std::net::IpAddr;
use std::process::Command;

const PREFIX: &str = "RvpnKit Block ";

#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub ip: String,
    pub name: String,
}

pub fn validate_ip(value: &str) -> Result<IpAddr, String> {
    let ip: IpAddr = value
        .trim()
        .parse()
        .map_err(|_| "请输入有效的 IPv4 或 IPv6 地址".to_string())?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
        return Err("不能阻断未指定、组播或本机回环地址".into());
    }
    Ok(ip)
}

pub fn block_ip(value: &str) -> Result<String, String> {
    let ip = validate_ip(value)?;
    ensure_windows()?;
    let name = format!("name={}", rule_name(&ip));
    let remote = format!("remoteip={ip}");
    run_netsh([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        name.as_str(),
        "dir=in",
        "action=block",
        remote.as_str(),
        "profile=any",
    ])?;
    Ok(format!("已阻断 {ip}"))
}

pub fn unblock_ip(value: &str) -> Result<String, String> {
    let ip = validate_ip(value)?;
    ensure_windows()?;
    let name = format!("name={}", rule_name(&ip));
    run_netsh(["advfirewall", "firewall", "delete", "rule", name.as_str()])?;
    Ok(format!("已解除阻断 {ip}"))
}

pub fn list_rules() -> Result<Vec<FirewallRule>, String> {
    ensure_windows()?;
    let output = run_netsh_output(["advfirewall", "firewall", "show", "rule", "name=all"])?;
    let mut rules = Vec::new();
    for line in output.lines() {
        let Some((_, value)) = line.trim().split_once(':') else {
            continue;
        };
        let name = value.trim();
        let Some(ip) = name.strip_prefix(PREFIX) else {
            continue;
        };
        if validate_ip(ip).is_ok() {
            rules.push(FirewallRule {
                ip: ip.into(),
                name: name.into(),
            });
        }
    }
    rules.sort_by(|a, b| a.ip.cmp(&b.ip));
    rules.dedup_by(|a, b| a.ip == b.ip);
    Ok(rules)
}

fn rule_name(ip: &IpAddr) -> String {
    format!("{PREFIX}{ip}")
}

fn ensure_windows() -> Result<(), String> {
    if cfg!(windows) {
        Ok(())
    } else {
        Err("防火墙管理仅支持 Windows".into())
    }
}

fn run_netsh<const N: usize>(args: [&str; N]) -> Result<(), String> {
    let mut command = Command::new("netsh.exe");
    command.args(args);
    quiet(&mut command);
    let output = command
        .output()
        .map_err(|e| format!("无法执行 Windows 防火墙命令：{e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn run_netsh_output<const N: usize>(args: [&str; N]) -> Result<String, String> {
    let mut command = Command::new("netsh.exe");
    command.args(args);
    quiet(&mut command);
    let output = command
        .output()
        .map_err(|e| format!("无法执行 Windows 防火墙命令：{e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn quiet(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
}

#[cfg(test)]
mod tests {
    use super::validate_ip;

    #[test]
    fn accepts_remote_addresses_and_rejects_local_or_reserved_targets() {
        assert!(validate_ip("203.0.113.20").is_ok());
        assert!(validate_ip("2001:db8::20").is_ok());
        assert!(validate_ip("127.0.0.1").is_err());
        assert!(validate_ip("0.0.0.0").is_err());
        assert!(validate_ip("224.0.0.1").is_err());
        assert!(validate_ip("not-an-ip").is_err());
    }
}
