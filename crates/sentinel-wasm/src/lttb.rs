/// Largest-Triangle-Three-Buckets (LTTB) downsampling (Sveinn Steinarsson, 2013).
/// Returns strictly ascending original point indices preserving first and last samples.
pub fn downsample_indices(xs: &[f64], ys: &[f64], threshold: usize) -> Vec<u32> {
    let n = xs.len().min(ys.len());
    if n == 0 || threshold == 0 {
        return Vec::new();
    }
    if threshold >= n || n <= 2 {
        return (0..n).map(|i| i as u32).collect();
    }
    if threshold == 1 {
        return vec![0];
    }
    if threshold == 2 {
        return vec![0, (n - 1) as u32];
    }

    let mut sampled = Vec::with_capacity(threshold);
    sampled.push(0_u32);

    let bucket_size = (n - 2) as f64 / (threshold - 2) as f64;
    let mut a: usize = 0;

    for i in 0..(threshold - 2) {
        let avg_start = (((i + 1) as f64) * bucket_size).floor() as usize + 1;
        let avg_end = ((((i + 2) as f64) * bucket_size).floor() as usize + 1).min(n);

        let mut avg_x = 0.0_f64;
        let mut avg_y = 0.0_f64;
        let mut avg_count = 0_usize;

        for idx in avg_start..avg_end {
            let x = xs[idx];
            let y = ys[idx];
            if x.is_finite() && y.is_finite() {
                avg_x += x;
                avg_y += y;
                avg_count += 1;
            }
        }

        if avg_count > 0 {
            avg_x /= avg_count as f64;
            avg_y /= avg_count as f64;
        } else {
            avg_x = xs[avg_start.min(n - 1)];
            avg_y = ys[avg_start.min(n - 1)];
        }

        let range_start = ((i as f64) * bucket_size).floor() as usize + 1;
        let range_end = ((((i + 1) as f64) * bucket_size).floor() as usize + 1).min(n - 1);

        let point_a_x = if xs[a].is_finite() { xs[a] } else { 0.0 };
        let point_a_y = if ys[a].is_finite() { ys[a] } else { 0.0 };

        let mut max_area = -1.0_f64;
        let mut next_a = range_start.min(n - 2);

        for idx in range_start..range_end {
            let px = xs[idx];
            let py = ys[idx];
            if !px.is_finite() || !py.is_finite() {
                continue;
            }
            let area = ((point_a_x - avg_x) * (py - point_a_y)
                - (point_a_x - px) * (avg_y - point_a_y))
                .abs()
                * 0.5;
            if area > max_area {
                max_area = area;
                next_a = idx;
            }
        }

        sampled.push(next_a as u32);
        a = next_a;
    }

    sampled.push((n - 1) as u32);
    sampled
}

/// Downsamples `(xs, ys)` to `threshold` points and returns interleaved `[x0, y0, x1, y1, ...]`.
pub fn downsample_xy(xs: &[f64], ys: &[f64], threshold: usize) -> Vec<f64> {
    let indices = downsample_indices(xs, ys, threshold);
    let mut out = Vec::with_capacity(indices.len() * 2);
    for idx in indices {
        let i = idx as usize;
        out.push(xs[i]);
        out.push(ys[i]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_empty_short_mismatched_and_non_finite_inputs() {
        assert!(downsample_indices(&[], &[], 10).is_empty());
        assert!(downsample_indices(&[1.0, 2.0], &[1.0, 2.0], 0).is_empty());
        assert_eq!(downsample_indices(&[1.0, 2.0], &[10.0, 20.0], 5), vec![0, 1]);
        assert_eq!(downsample_indices(&[1.0, 2.0, 3.0], &[10.0, 20.0, 30.0], 1), vec![0]);
        assert_eq!(downsample_indices(&[1.0, 2.0, 3.0], &[10.0, 20.0, 30.0], 2), vec![0, 2]);
        // Mismatched lengths use min len
        assert_eq!(downsample_indices(&[1.0, 2.0, 3.0, 4.0], &[10.0, 20.0], 10), vec![0, 1]);
        // NaN points do not panic
        let idx = downsample_indices(
            &[0.0, 1.0, 2.0, 3.0, 4.0, 5.0],
            &[10.0, f64::NAN, 12.0, 80.0, 11.0, 10.0],
            4,
        );
        assert_eq!(idx.len(), 4);
        assert_eq!(idx[0], 0);
        assert_eq!(idx[3], 5);
    }

    #[test]
    fn preserves_sharp_spike_in_large_series() {
        let n = 10_000_usize;
        let xs: Vec<f64> = (0..n).map(|i| i as f64 * 1000.0).collect();
        let mut ys = vec![20.0_f64; n];
        ys[4321] = 99.5;

        let indices = downsample_indices(&xs, &ys, 60);
        assert_eq!(indices.len(), 60);
        assert_eq!(indices[0], 0);
        assert_eq!(indices[59], (n - 1) as u32);
        assert!(indices.windows(2).all(|w| w[0] < w[1]));
        assert!(
            indices.contains(&4321),
            "LTTB must preserve the 99.5 spike at index 4321"
        );

        let xy = downsample_xy(&xs, &ys, 60);
        assert_eq!(xy.len(), 120);
        assert!(xy.iter().any(|&v| (v - 99.5).abs() < 1e-6));
    }
}
