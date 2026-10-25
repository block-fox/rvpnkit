//! Windows 命名管道传输。
//!
//! 只做三件事：打开管道、写一帧、把一段时间内的数据读回来。
//!
//! 这里不引 `windows-sys`，直接声明需要的 5 个 kernel32 函数 —— 依赖更少，
//! 也不用在特征特性（feature）上猜来猜去。
//!
//! ## 关于访问权限的一个坑
//!
//! 用 `GENERIC_READ | GENERIC_WRITE` 打开时，如果进程运行在 **Low 完整性**
//! （某些沙箱会把子进程降权），会得到 `ERROR_ACCESS_DENIED(5)`，而只读却成功。
//! 这不是代码问题 —— 管道的强制完整性策略要求 Medium 才允许写。
//! 所以这里读写失败时降级为只读，并把状态暴露给上层。

#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

type Handle = *mut core::ffi::c_void;
type Bool = i32;
type Dword = u32;

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: Dword,
        share_mode: Dword,
        security_attributes: *mut core::ffi::c_void,
        creation_disposition: Dword,
        flags_and_attributes: Dword,
        template_file: Handle,
    ) -> Handle;

    fn ReadFile(
        file: Handle,
        buffer: *mut u8,
        bytes_to_read: Dword,
        bytes_read: *mut Dword,
        overlapped: *mut core::ffi::c_void,
    ) -> Bool;

    fn WriteFile(
        file: Handle,
        buffer: *const u8,
        bytes_to_write: Dword,
        bytes_written: *mut Dword,
        overlapped: *mut core::ffi::c_void,
    ) -> Bool;

    fn PeekNamedPipe(
        named_pipe: Handle,
        buffer: *mut core::ffi::c_void,
        buffer_size: Dword,
        bytes_read: *mut Dword,
        total_bytes_avail: *mut Dword,
        bytes_left_this_message: *mut Dword,
    ) -> Bool;

    fn CloseHandle(object: Handle) -> Bool;

    fn GetLastError() -> u32;
}

const GENERIC_READ: Dword = 0x8000_0000;
const GENERIC_WRITE: Dword = 0x4000_0000;
const FILE_SHARE_READ: Dword = 0x0000_0001;
const FILE_SHARE_WRITE: Dword = 0x0000_0002;
const OPEN_EXISTING: Dword = 3;
const INVALID_HANDLE_VALUE: Handle = usize::MAX as Handle;

/// 管道操作错误。
#[derive(Debug)]
pub struct PipeError {
    /// Win32 错误码。
    pub code: u32,
    /// 说明。
    pub message: String,
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}（Win32 {}）", self.message, self.code)
    }
}

impl std::error::Error for PipeError {}

fn last_error(message: &str) -> PipeError {
    PipeError {
        code: unsafe { GetLastError() },
        message: message.to_string(),
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// 控制管道客户端。
pub struct PipeClient {
    handle: Handle,
    can_write: bool,
    path: String,
}

// 句柄是进程内资源；同一时刻只由一个线程使用。
unsafe impl Send for PipeClient {}

impl PipeClient {
    /// Wait for the explicit completion carrying this request ID. An initial
    /// snapshot or unrelated event never counts as a successful command.
    pub fn transact(
        &mut self,
        frame: &[u8],
        timeout: Duration,
    ) -> Result<crate::operation::Completion, PipeError> {
        let request_id = crate::Wire::request_id(frame);
        self.send(frame)?;
        let started = Instant::now();
        let mut data = Vec::new();
        let mut buffer = vec![0u8; 65536];
        while started.elapsed() < timeout {
            let mut available: Dword = 0;
            if unsafe {
                PeekNamedPipe(
                    self.handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(last_error("等待回执时管道断开"));
            }
            if available > 0 {
                let mut got: Dword = 0;
                let count = (available as usize).min(buffer.len());
                if unsafe {
                    ReadFile(
                        self.handle,
                        buffer.as_mut_ptr(),
                        count as Dword,
                        &mut got,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(last_error("读取服务回执失败"));
                }
                if data.len() + got as usize > 8 * 1024 * 1024 {
                    return Err(PipeError {
                        code: 0,
                        message: "服务回执超过 8 MiB 限制".into(),
                    });
                }
                data.extend_from_slice(&buffer[..got as usize]);
                if let Some(completion) = crate::operation::Completion::find(&data, request_id) {
                    return completion
                        .into_result()
                        .map_err(|message| PipeError { code: 0, message });
                }
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Err(PipeError {
            code: 1460,
            message: format!("请求 #{request_id} 已发送，但未收到服务确认；请刷新核对，勿重复提交"),
        })
    }
    /// 连接控制管道。读写失败会自动降级为只读。
    pub fn connect(path: &str) -> Result<Self, PipeError> {
        let w = wide(path);

        let handle = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            return Ok(Self {
                handle,
                can_write: true,
                path: path.to_string(),
            });
        }

        let first = unsafe { GetLastError() };

        let handle = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error(&format!(
                "打开管道失败（读写模式曾返回 {first}）"
            )));
        }

        Ok(Self {
            handle,
            can_write: false,
            path: path.to_string(),
        })
    }

    /// 是否可写。
    pub fn can_write(&self) -> bool {
        self.can_write
    }

    /// 管道路径。
    pub fn path(&self) -> &str {
        &self.path
    }

    /// 发送一条命令正文（自动补 4 字节小端长度前缀）。
    pub fn send(&mut self, frame: &[u8]) -> Result<(), PipeError> {
        if !self.can_write {
            return Err(PipeError {
                code: 5,
                message: "当前为只读连接，无法下发命令".into(),
            });
        }

        let mut buf = Vec::with_capacity(frame.len() + 4);
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(frame);

        let mut wrote: Dword = 0;
        let ok = unsafe {
            WriteFile(
                self.handle,
                buf.as_ptr(),
                buf.len() as Dword,
                &mut wrote,
                std::ptr::null_mut(),
            )
        };

        if ok == 0 {
            return Err(last_error("写入管道失败"));
        }
        if wrote as usize != buf.len() {
            return Err(PipeError {
                code: 0,
                message: format!("写入不完整：{wrote}/{}", buf.len()),
            });
        }
        Ok(())
    }

    /// 读取一段快照数据。
    ///
    /// 用 `PeekNamedPipe` 轮询可读字节，这样能在不阻塞线程的前提下实现超时；
    /// 一旦有数据后空闲超过 120ms 就认为这一批读完。
    pub fn read_snapshot(&mut self, timeout: Duration) -> Result<Vec<u8>, PipeError> {
        let start = Instant::now();
        let idle = Duration::from_millis(120);
        let mut out = Vec::new();
        let mut last_data = Instant::now();
        let mut buf = vec![0u8; 64 * 1024];

        while start.elapsed() < timeout {
            let mut available: Dword = 0;
            let ok = unsafe {
                PeekNamedPipe(
                    self.handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                break; // 管道已断
            }

            if available > 0 {
                let want = (available as usize).min(buf.len());
                let mut got: Dword = 0;
                let ok = unsafe {
                    ReadFile(
                        self.handle,
                        buf.as_mut_ptr(),
                        want as Dword,
                        &mut got,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 || got == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..got as usize]);
                if out.len() > 8 * 1024 * 1024 {
                    return Err(PipeError {
                        code: 0,
                        message: "快照超过 8 MiB 限制".into(),
                    });
                }
                last_data = Instant::now();
            } else {
                if !out.is_empty() && last_data.elapsed() > idle {
                    break;
                }
                std::thread::sleep(Duration::from_millis(8));
            }
        }

        Ok(out)
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && !self.handle.is_null() {
            unsafe { CloseHandle(self.handle) };
        }
    }
}
