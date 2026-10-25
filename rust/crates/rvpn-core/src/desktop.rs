//! Allow-listed Windows integrations; no shell interpolation or arbitrary commands.
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::{net::IpAddr, path::PathBuf, process::Command};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAction {
    Official,
    Logs,
    Adapters,
    Help,
    Community,
    Bug,
    Feature,
    InstallServer,
    Ping,
    SharedFolders,
    FullControl,
    ViewOnly,
    FileTransfer,
    Telnet,
    RemoteShutdown,
    Chat,
    VoiceChat,
    SendMessage,
    IpBackup,
    IpReset,
    IpChangeMac,
}
pub const VIEWER_ACTIONS: [(DesktopAction, &str); 8] = [
    (DesktopAction::FullControl, "完全控制"),
    (DesktopAction::ViewOnly, "仅查看"),
    (DesktopAction::FileTransfer, "文件传输"),
    (DesktopAction::Telnet, "Telnet"),
    (DesktopAction::RemoteShutdown, "远程关机"),
    (DesktopAction::Chat, "Radmin 文本聊天"),
    (DesktopAction::VoiceChat, "Radmin 语音聊天"),
    (DesktopAction::SendMessage, "发送消息"),
];

/// Ask Windows for elevation before opening the local control pipe.
/// Returns true when an elevated child was started and the current process
/// should exit. Demo and HTTP-agent modes do not need elevation.
pub fn maybe_relaunch_elevated() -> Result<bool, String> {
    if !cfg!(windows)
        || std::env::args().any(|arg| arg == "--rvpnkit-elevated")
        || std::env::args().any(|arg| arg == "--demo" || arg == "--agent")
    {
        return Ok(false);
    }
    #[cfg(windows)]
    unsafe {
        #[link(name = "shell32")]
        extern "system" {
            fn IsUserAnAdmin() -> i32;
            fn ShellExecuteW(
                hwnd: *mut core::ffi::c_void,
                operation: *const u16,
                file: *const u16,
                parameters: *const u16,
                directory: *const u16,
                show: i32,
            ) -> isize;
        }
        if IsUserAnAdmin() != 0 {
            return Ok(false);
        }
        let exe = std::env::current_exe().map_err(|e| format!("无法定位程序路径：{e}"))?;
        let mut args = String::from("--rvpnkit-elevated");
        for arg in std::env::args().skip(1) {
            if arg == "--rvpnkit-elevated" {
                continue;
            }
            args.push(' ');
            args.push_str(&quote_windows_arg(&arg));
        }
        let wide = |value: &std::ffi::OsStr| {
            value
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        };
        let verb = wide(std::ffi::OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let params = wide(std::ffi::OsStr::new(&args));
        let result = ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            1,
        );
        if result <= 32 {
            return Err("管理员权限请求被取消或启动失败；当前将保持只读模式".into());
        }
        return Ok(true);
    }
    #[cfg(not(windows))]
    Ok(false)
}

#[cfg(windows)]
fn quote_windows_arg(value: &str) -> String {
    if value.is_empty() || value.chars().any(char::is_whitespace) || value.contains('"') {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_owned()
    }
}

/// Measure an actual virtual address instead of trusting a stale snapshot
/// latency field. The elapsed time includes a small process-launch overhead,
/// so the UI labels this as a measured reachability value.
pub fn probe_latency(address: &str) -> Result<Option<u32>, String> {
    let ip: IpAddr = address
        .parse()
        .map_err(|_| "需要有效的虚拟 IP 地址".to_string())?;
    let started = std::time::Instant::now();
    let mut command = if cfg!(windows) {
        let mut command = Command::new("ping.exe");
        command.args(["-n", "1", "-w", "700", &ip.to_string()]);
        command
    } else {
        let mut command = Command::new("ping");
        command.args(["-c", "1", "-W", "1", &ip.to_string()]);
        command
    };
    quiet(&mut command);
    let output = command.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        started.elapsed().as_millis().min(u32::MAX as u128) as u32
    ))
}

pub fn probe_many(addresses: &[String]) -> Vec<(String, Option<u32>)> {
    let mut unique = Vec::new();
    for address in addresses {
        if address.parse::<IpAddr>().is_ok() && !unique.contains(address) {
            unique.push(address.clone());
        }
    }
    unique.truncate(48);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for address in unique {
            handles.push(scope.spawn(move || {
                let result = probe_latency(&address).ok().flatten();
                (address, result)
            }));
        }
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    })
}
pub fn install_directory() -> PathBuf {
    std::env::var_os("ProgramFiles(x86)")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)"))
        .join("Radmin VPN")
}
pub fn official_path() -> PathBuf {
    install_directory().join("RvRvpnGui.exe")
}
pub fn viewer_path() -> Option<PathBuf> {
    [
        install_directory().join("Radmin.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Radmin Viewer 3\Radmin.exe"),
        PathBuf::from(r"C:\Program Files\Radmin Viewer 3\Radmin.exe"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}
pub fn viewer_arguments(action: DesktopAction, address: &str) -> Result<Vec<String>, String> {
    let ip: IpAddr = address.parse().map_err(|_| "需要有效的虚拟 IP 地址")?;
    let switch = match action {
        DesktopAction::FullControl => None,
        DesktopAction::ViewOnly => Some("/noinput"),
        DesktopAction::FileTransfer => Some("/file"),
        DesktopAction::Telnet => Some("/telnet"),
        DesktopAction::RemoteShutdown => Some("/shutdown"),
        DesktopAction::Chat => Some("/chat"),
        DesktopAction::VoiceChat => Some("/voice"),
        DesktopAction::SendMessage => Some("/message"),
        _ => return Err("这不是 Radmin Viewer 操作".into()),
    };
    let mut args = vec![format!("/connect:{ip}")];
    if let Some(s) = switch {
        args.push(s.into());
    }
    Ok(args)
}
fn quiet(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(not(windows))]
    let _ = command;
}
fn launch(exe: impl AsRef<std::ffi::OsStr>, args: &[String]) -> Result<String, String> {
    let mut command = Command::new(exe);
    command.args(args);
    quiet(&mut command);
    command.spawn().map_err(|e| e.to_string())?;
    Ok("已打开系统或官方组件".into())
}
pub fn execute(action: DesktopAction, address: Option<&str>) -> Result<String, String> {
    if !cfg!(windows) {
        return Err("系统集成仅适用于 Windows".into());
    }
    match action {
        DesktopAction::Official => {
            let p = official_path();
            if !p.is_file() {
                return Err("未找到官方客户端，请先安装 Radmin VPN".into());
            }
            launch(p, &["/show".into()])
        }
        DesktopAction::Logs => {
            let p = std::env::var_os("PROGRAMDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
                .join("Famatech")
                .join("Radmin VPN");
            launch("explorer.exe", &[p.display().to_string()])
        }
        DesktopAction::Adapters => launch("control.exe", &["ncpa.cpl".into()]),
        DesktopAction::Help
        | DesktopAction::Community
        | DesktopAction::Bug
        | DesktopAction::Feature => {
            let url = match action {
                DesktopAction::Help => "https://www.radmin-vpn.com/help/",
                DesktopAction::Community => "https://www.radmin-vpn.com/communities/",
                _ => "https://www.radmin-vpn.com/support/",
            };
            launch("explorer.exe", &[url.into()])
        }
        DesktopAction::InstallServer => {
            let path = install_directory().join("rserv35ml.msi");
            if !path.is_file() {
                return Err("未找到官方 Radmin Server 安装程序".into());
            }
            launch("msiexec.exe", &["/i".into(), path.display().to_string()])
        }
        DesktopAction::Ping => {
            let ip: IpAddr = address
                .ok_or("请选择一个有虚拟 IP 的成员")?
                .parse()
                .map_err(|_| "地址无效")?;
            let mut cmd = Command::new("ping.exe");
            cmd.args(["-n", "4", "-w", "1000", &ip.to_string()]);
            quiet(&mut cmd);
            let out = cmd.output().map_err(|e| e.to_string())?;
            let mut bytes = out.stdout;
            bytes.extend(out.stderr);
            Ok(decode_output(&bytes))
        }
        DesktopAction::SharedFolders => {
            let ip: std::net::Ipv4Addr = address
                .ok_or("需要虚拟 IPv4")?
                .parse()
                .map_err(|_| "共享文件夹需要 IPv4 地址")?;
            launch("explorer.exe", &[format!(r"\\{ip}\")])
        }
        DesktopAction::IpBackup | DesktopAction::IpReset | DesktopAction::IpChangeMac => {
            let script = match action {
                DesktopAction::IpBackup => "backup-ip.ps1",
                DesktopAction::IpReset => "reset-ip.ps1",
                DesktopAction::IpChangeMac => "change-mac.ps1",
                _ => unreachable!(),
            };
            let path = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("RadminVPN-IP-Tools").join("scripts").join(script)))
                .filter(|p| p.is_file())
                .ok_or_else(|| format!("未找到可选 IP 工具：请将 AXFJ 工具的 scripts 放到程序目录\\RadminVPN-IP-Tools\\scripts\\{script}"))?;
            launch(
                "powershell.exe",
                &[
                    "-NoProfile".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-File".into(),
                    path.display().to_string(),
                ],
            )
        }
        _ => {
            let viewer =
                viewer_path().ok_or("未找到 Radmin Viewer；此功能还需要对端安装 Radmin Server")?;
            launch(
                viewer,
                &viewer_arguments(action, address.ok_or("需要成员虚拟 IP")?)?,
            )
        }
    }
}
fn decode_output(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_owned();
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn MultiByteToWideChar(
                code: u32,
                flags: u32,
                input: *const u8,
                size: i32,
                output: *mut u16,
                count: i32,
            ) -> i32;
        }
        let count = unsafe {
            MultiByteToWideChar(
                1,
                0,
                bytes.as_ptr(),
                bytes.len() as i32,
                std::ptr::null_mut(),
                0,
            )
        };
        if count > 0 {
            let mut text = vec![0u16; count as usize];
            unsafe {
                MultiByteToWideChar(
                    1,
                    0,
                    bytes.as_ptr(),
                    bytes.len() as i32,
                    text.as_mut_ptr(),
                    count,
                )
            };
            return String::from_utf16_lossy(&text);
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_shell_or_host_injection() {
        for input in ["26.0.0.1 & calc.exe", "-n 100", "example.com", "\\\\host"] {
            assert!(viewer_arguments(DesktopAction::FullControl, input).is_err());
        }
    }
    #[test]
    fn uses_separate_arguments_for_modes() {
        assert_eq!(
            viewer_arguments(DesktopAction::ViewOnly, "26.0.0.1").unwrap(),
            vec!["/connect:26.0.0.1", "/noinput"]
        );
        assert!(viewer_arguments(DesktopAction::Official, "26.0.0.1").is_err());
    }
}
