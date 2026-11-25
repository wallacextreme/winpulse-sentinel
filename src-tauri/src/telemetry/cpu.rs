/// Computes global CPU busy percentage from two Win32 `GetSystemTimes` snapshots.
///
/// On Windows, `kernel` includes `idle` time, so total elapsed CPU time is
/// `delta_kernel + delta_user` and busy time is `delta_total - delta_idle`.
pub(crate) fn compute_busy_percent(
    prev_idle: u64,
    prev_kernel: u64,
    prev_user: u64,
    idle: u64,
    kernel: u64,
    user: u64,
) -> Option<f32> {
    let delta_idle = idle.saturating_sub(prev_idle);
    let delta_kernel = kernel.saturating_sub(prev_kernel);
    let delta_user = user.saturating_sub(prev_user);
    let delta_total = delta_kernel.saturating_add(delta_user);
    if delta_total == 0 {
        return None;
    }

    let delta_busy = delta_total.saturating_sub(delta_idle);
    let pct = ((delta_busy as f64 / delta_total as f64) * 100.0) as f32;
    if pct.is_finite() {
        Some(pct.clamp(0.0, 100.0))
    } else {
        Some(0.0)
    }
}

#[cfg(windows)]
mod win_cpu {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetSystemTimes;

    use super::compute_busy_percent;

    #[inline]
    fn filetime_to_u64(ft: FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }

    fn read_system_times() -> Option<(u64, u64, u64)> {
        let mut idle = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let res = unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) };
        if res.is_err() {
            return None;
        }
        Some((
            filetime_to_u64(idle),
            filetime_to_u64(kernel),
            filetime_to_u64(user),
        ))
    }

    /// Global CPU usage monitor backed directly by Win32 `GetSystemTimes`,
    /// avoiding PDH `\Processor(_Total)\% Idle Time` failures on hosts with broken PerfLib counters.
    pub struct CpuMonitor {
        prev_idle: u64,
        prev_kernel: u64,
        prev_user: u64,
        has_baseline: bool,
        last_percent: f32,
    }

    impl CpuMonitor {
        pub fn new() -> Self {
            if let Some((idle, kernel, user)) = read_system_times() {
                Self {
                    prev_idle: idle,
                    prev_kernel: kernel,
                    prev_user: user,
                    has_baseline: true,
                    last_percent: 0.0,
                }
            } else {
                Self {
                    prev_idle: 0,
                    prev_kernel: 0,
                    prev_user: 0,
                    has_baseline: false,
                    last_percent: 0.0,
                }
            }
        }

        pub fn sample(&mut self, sys: &mut sysinfo::System) -> f32 {
            let Some((idle, kernel, user)) = read_system_times() else {
                sys.refresh_cpu_usage();
                return sys.global_cpu_usage().clamp(0.0, 100.0);
            };

            if !self.has_baseline {
                self.prev_idle = idle;
                self.prev_kernel = kernel;
                self.prev_user = user;
                self.has_baseline = true;
                return self.last_percent;
            }

            if let Some(pct) = compute_busy_percent(
                self.prev_idle,
                self.prev_kernel,
                self.prev_user,
                idle,
                kernel,
                user,
            ) {
                self.prev_idle = idle;
                self.prev_kernel = kernel;
                self.prev_user = user;
                self.last_percent = pct;
                pct
            } else {
                self.last_percent
            }
        }
    }

    impl Default for CpuMonitor {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(not(windows))]
mod win_cpu {
    /// Global CPU usage monitor delegating to `sysinfo` on non-Windows targets.
    pub struct CpuMonitor;

    impl CpuMonitor {
        pub fn new() -> Self {
            Self
        }

        pub fn sample(&mut self, sys: &mut sysinfo::System) -> f32 {
            sys.refresh_cpu_usage();
            sys.global_cpu_usage().clamp(0.0, 100.0)
        }
    }

    impl Default for CpuMonitor {
        fn default() -> Self {
            Self::new()
        }
    }
}

pub use win_cpu::CpuMonitor;

#[cfg(test)]
mod tests {
    use super::*;
    use sysinfo::{CpuRefreshKind, RefreshKind, System};

    #[test]
    fn computes_expected_busy_percentages_from_kernel_user_idle_deltas() {
        // 0% idle => 100% busy
        assert_eq!(
            compute_busy_percent(100, 500, 300, 100, 1000, 800),
            Some(100.0)
        );
        // 100% idle => 0% busy (kernel delta == idle delta, user delta == 0)
        assert_eq!(
            compute_busy_percent(100, 500, 300, 1100, 1500, 300),
            Some(0.0)
        );
        // 25% busy (total delta = 800 + 200 = 1000, idle delta = 750 => busy = 250 => 25.0%)
        assert_eq!(
            compute_busy_percent(10, 20, 30, 760, 820, 230),
            Some(25.0)
        );
        // Zero delta => None
        assert_eq!(compute_busy_percent(50, 100, 20, 50, 100, 20), None);
    }

    #[test]
    fn cpu_monitor_reports_strictly_positive_usage_under_load() {
        let refresh = RefreshKind::nothing().with_cpu(if cfg!(windows) {
            CpuRefreshKind::nothing()
        } else {
            CpuRefreshKind::nothing().with_usage()
        });
        let mut sys = System::new_with_specifics(refresh).expect("init sysinfo");
        let mut monitor = CpuMonitor::new();

        let worker = std::thread::spawn(|| {
            let start = std::time::Instant::now();
            let mut acc = 0_u64;
            while start.elapsed() < std::time::Duration::from_millis(250) {
                acc = acc.wrapping_add(1);
                std::hint::black_box(acc);
            }
        });
        let _ = worker.join();

        let usage = monitor.sample(&mut sys);
        assert!(
            usage > 0.0 && usage <= 100.0,
            "expected strictly positive CPU usage under load, got {usage}"
        );
    }
}
