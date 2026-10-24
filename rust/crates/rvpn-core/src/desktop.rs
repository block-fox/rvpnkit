//! Allow-listed Windows integrations; no shell interpolation or arbitrary commands.
use serde::{Deserialize, Serialize};
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
