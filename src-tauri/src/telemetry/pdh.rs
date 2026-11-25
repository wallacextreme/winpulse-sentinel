#[cfg(windows)]
mod win_pdh {
    use core::ffi::c_void;
    use windows::core::{w, HSTRING, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::{DISK_PERFORMANCE, IOCTL_DISK_PERFORMANCE};
    use windows::Win32::System::Performance::{
        PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue,
        PdhOpenQueryW, PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY,
    };

    struct PdhBackend {
        query: PDH_HQUERY,
        active_or_idle_counter: PDH_HCOUNTER,
        is_idle_counter: bool,
        latency_counter: PDH_HCOUNTER,
        primed: bool,
    }

    impl PdhBackend {
        fn try_open() -> Option<Self> {
            let candidates = [
                (
                    w!(r"\PhysicalDisk(_Total)\% Idle Time"),
                    true,
                    w!(r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer"),
                ),
                (
                    w!(r"\LogicalDisk(_Total)\% Idle Time"),
                    true,
                    w!(r"\LogicalDisk(_Total)\Avg. Disk sec/Transfer"),
                ),
                (
                    w!(r"\PhysicalDisk(_Total)\% Disk Time"),
                    false,
                    w!(r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer"),
                ),
            ];

            for (active_path, is_idle_counter, latency_path) in candidates {
                unsafe {
                    let mut query = PDH_HQUERY::default();
                    if PdhOpenQueryW(PCWSTR::null(), 0, &mut query) != 0 {
                        continue;
                    }

                    let mut active_or_idle_counter = PDH_HCOUNTER::default();
                    if PdhAddEnglishCounterW(query, active_path, 0, &mut active_or_idle_counter)
                        != 0
                    {
                        let _ = PdhCloseQuery(query);
                        continue;
                    }

                    let mut latency_counter = PDH_HCOUNTER::default();
                    if PdhAddEnglishCounterW(query, latency_path, 0, &mut latency_counter) != 0 {
                        let _ = PdhCloseQuery(query);
                        continue;
                    }

                    let primed = PdhCollectQueryData(query) == 0;
                    return Some(Self {
                        query,
                        active_or_idle_counter,
                        is_idle_counter,
                        latency_counter,
                        primed,
                    });
                }
            }
            None
        }

        fn sample(&mut self) -> Option<(f32, f32)> {
            unsafe {
                if PdhCollectQueryData(self.query) != 0 {
                    return None;
                }
                if !self.primed {
                    self.primed = true;
                    return Some((0.0, 0.0));
                }

                let mut active_val = PDH_FMT_COUNTERVALUE::default();
                let active_ok = PdhGetFormattedCounterValue(
                    self.active_or_idle_counter,
                    PDH_FMT_DOUBLE,
                    None,
                    &mut active_val,
                ) == 0;

                let active_pct = if active_ok {
                    let raw = active_val.Anonymous.doubleValue;
                    if raw.is_finite() {
                        let pct = if self.is_idle_counter {
                            100.0 - raw
                        } else {
                            raw
                        };
                        (pct as f32).clamp(0.0, 100.0)
                    } else {
                        0.0
                    }
                } else {
                    return None;
                };

                let mut latency_val = PDH_FMT_COUNTERVALUE::default();
                let latency_ms = if PdhGetFormattedCounterValue(
                    self.latency_counter,
                    PDH_FMT_DOUBLE,
                    None,
                    &mut latency_val,
                ) == 0
                {
                    let raw_sec = latency_val.Anonymous.doubleValue;
                    if raw_sec.is_finite() && raw_sec >= 0.0 {
                        (raw_sec * 1000.0) as f32
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };

                Some((active_pct, latency_ms))
            }
        }
    }

    impl Drop for PdhBackend {
        fn drop(&mut self) {
            unsafe {
                let _ = PdhCloseQuery(self.query);
            }
        }
    }

    struct DriveHandle {
        handle: HANDLE,
        prev: Option<DISK_PERFORMANCE>,
    }

    impl Drop for DriveHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }

    /// Direct Win32 storage driver telemetry (`IOCTL_DISK_PERFORMANCE`), immune to disabled PDH counters.
    struct IoctlDiskBackend {
        drives: Vec<DriveHandle>,
    }

    impl IoctlDiskBackend {
        fn try_open() -> Option<Self> {
            let mut drives = Vec::new();
            let device_paths = [
                r"\\.\PhysicalDrive0",
                r"\\.\PhysicalDrive1",
                r"\\.\PhysicalDrive2",
                r"\\.\PhysicalDrive3",
            ];

            for path in device_paths {
                if let Some(d) = Self::open_device(path) {
                    drives.push(d);
                }
            }

            if drives.is_empty() {
                if let Some(d) = Self::open_device(r"\\.\C:") {
                    drives.push(d);
                }
            }

            if drives.is_empty() {
                None
            } else {
                Some(Self { drives })
            }
        }

        fn open_device(path: &str) -> Option<DriveHandle> {
            let path_h = HSTRING::from(path);
            let handle = unsafe {
                CreateFileW(
                    &path_h,
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    None,
                )
                .ok()?
            };

            let initial = Self::query_perf(handle);
            if initial.is_none() {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return None;
            }

            Some(DriveHandle {
                handle,
                prev: initial,
            })
        }

        fn query_perf(handle: HANDLE) -> Option<DISK_PERFORMANCE> {
            let mut perf = DISK_PERFORMANCE::default();
            let mut bytes_returned: u32 = 0;
            let ok = unsafe {
                DeviceIoControl(
                    handle,
                    IOCTL_DISK_PERFORMANCE,
                    None,
                    0,
                    Some((&mut perf as *mut DISK_PERFORMANCE).cast::<c_void>()),
                    std::mem::size_of::<DISK_PERFORMANCE>() as u32,
                    Some(&mut bytes_returned),
                    None,
                )
                .is_ok()
            };
            if ok {
                Some(perf)
            } else {
                None
            }
        }

        fn sample(&mut self) -> (f32, f32) {
            let mut max_active_pct = 0.0_f32;
            let mut max_latency_ms = 0.0_f32;

            for drive in &mut self.drives {
                let Some(curr) = Self::query_perf(drive.handle) else {
                    continue;
                };
                if let Some(prev) = drive.prev {
                    let delta_query = curr.QueryTime.saturating_sub(prev.QueryTime);
                    if delta_query > 0 {
                        let delta_idle = curr
                            .IdleTime
                            .saturating_sub(prev.IdleTime)
                            .clamp(0, delta_query);
                        let active_pct =
                            ((1.0 - (delta_idle as f64 / delta_query as f64)) * 100.0)
                                .clamp(0.0, 100.0) as f32;
                        if active_pct > max_active_pct {
                            max_active_pct = active_pct;
                        }
                    }

                    let delta_reads = curr.ReadCount.wrapping_sub(prev.ReadCount) as u64;
                    let delta_writes = curr.WriteCount.wrapping_sub(prev.WriteCount) as u64;
                    let total_ops = delta_reads.saturating_add(delta_writes);
                    if total_ops > 0 {
                        let delta_read_t = curr.ReadTime.saturating_sub(prev.ReadTime).max(0) as f64;
                        let delta_write_t =
                            curr.WriteTime.saturating_sub(prev.WriteTime).max(0) as f64;
                        let avg_ms = ((delta_read_t + delta_write_t) / 10_000.0) / total_ops as f64;
                        if avg_ms.is_finite() && (avg_ms as f32) > max_latency_ms {
                            max_latency_ms = avg_ms as f32;
                        }
                    }
                }
                drive.prev = Some(curr);
            }

            (max_active_pct, max_latency_ms)
        }
    }

    pub struct PdhDiskMonitor {
        pdh: Option<PdhBackend>,
        ioctl: Option<IoctlDiskBackend>,
    }

    // Handles are strictly owned and polled sequentially by the single telemetry task.
    unsafe impl Send for PdhDiskMonitor {}

    impl PdhDiskMonitor {
        pub fn new() -> Option<Self> {
            let pdh = PdhBackend::try_open();
            let ioctl = IoctlDiskBackend::try_open();

            if pdh.is_none() && ioctl.is_none() {
                tracing::warn!(
                    "Both PDH and IOCTL_DISK_PERFORMANCE disk monitors unavailable; disk metrics fallback active"
                );
                return None;
            }

            tracing::info!(
                pdh_active = pdh.is_some(),
                ioctl_active = ioctl.is_some(),
                "Windows Disk Telemetry Monitor initialized"
            );

            Some(Self { pdh, ioctl })
        }

        pub fn sample(&mut self) -> (f32, f32) {
            let ioctl_res = self.ioctl.as_mut().map(|b| b.sample());
            let pdh_res = self.pdh.as_mut().and_then(|b| b.sample());

            match (ioctl_res, pdh_res) {
                (Some((ia, il)), Some((pa, pl))) => (ia.max(pa), il.max(pl)),
                (Some(res), None) => res,
                (None, Some(res)) => res,
                (None, None) => (0.0, 0.0),
            }
        }
    }
}

#[cfg(not(windows))]
mod win_pdh {
    pub struct PdhDiskMonitor;

    impl PdhDiskMonitor {
        pub fn new() -> Option<Self> {
            None
        }

        pub fn sample(&mut self) -> (f32, f32) {
            (0.0, 0.0)
        }
    }
}

pub use win_pdh::PdhDiskMonitor;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn initializes_windows_disk_monitor_and_samples_finite_values() {
        let mut mon =
            PdhDiskMonitor::new().expect("at least PDH or IOCTL disk monitor must open");
        std::thread::sleep(std::time::Duration::from_millis(120));
        let (active_pct, latency_ms) = mon.sample();
        assert!(active_pct.is_finite() && (0.0..=100.0).contains(&active_pct));
        assert!(latency_ms.is_finite() && latency_ms >= 0.0);
    }
}
