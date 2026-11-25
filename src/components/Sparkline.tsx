import { useId, useMemo } from "react";
import { downsampleSeriesXY } from "../wasm/sentinelWasm";

interface SparklineProps {
  timestamps: number[];
  values: number[];
  maxY: number;
  thresholdY?: number;
  color: string;
  wasmReady: boolean;
  targetPoints?: number;
  height?: number;
}

export function Sparkline({
  timestamps,
  values,
  maxY,
  thresholdY,
  color,
  wasmReady,
  targetPoints = 42,
  height = 52,
}: SparklineProps) {
  const gradientId = useId();
  const width = 260;
  const padY = 4;

  const { linePath, areaPath, lastPoint } = useMemo(() => {
    const count = Math.min(timestamps.length, values.length);
    if (count === 0) {
      return { linePath: "", areaPath: "", lastPoint: null };
    }

    let sampledX: number[] = [];
    let sampledY: number[] = [];

    if (wasmReady && count > targetPoints && targetPoints >= 3) {
      const xs = new Float64Array(count);
      const ys = new Float64Array(count);
      for (let i = 0; i < count; i++) {
        xs[i] = timestamps[i] ?? i;
        ys[i] = values[i] ?? 0;
      }
      const xy = downsampleSeriesXY(xs, ys, targetPoints);
      for (let i = 0; i + 1 < xy.length; i += 2) {
        sampledX.push(xy[i] ?? 0);
        sampledY.push(xy[i + 1] ?? 0);
      }
    } else {
      sampledX = timestamps.slice(0, count);
      sampledY = values.slice(0, count);
    }

    const n = sampledY.length;
    if (n === 0) {
      return { linePath: "", areaPath: "", lastPoint: null };
    }

    const minX = sampledX[0] ?? 0;
    const maxX = sampledX[n - 1] ?? minX + 1;
    const spanX = Math.max(maxX - minX, 1);
    const safeMaxY = Math.max(maxY, 1);
    const usableH = height - padY * 2;

    const coords = sampledY.map((val, idx) => {
      const x =
        n === 1
          ? width
          : (((sampledX[idx] ?? minX) - minX) / spanX) * width;
      const clamped = Math.max(0, Math.min(val, safeMaxY));
      const y = height - padY - (clamped / safeMaxY) * usableH;
      return { x, y };
    });

    const line = coords
      .map((pt, i) => `${i === 0 ? "M" : "L"} ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`)
      .join(" ");
    const first = coords[0];
    const last = coords[coords.length - 1] ?? null;
    const area =
      first && last
        ? `${line} L ${last.x.toFixed(1)} ${height} L ${first.x.toFixed(1)} ${height} Z`
        : "";

    return { linePath: line, areaPath: area, lastPoint: last };
  }, [height, maxY, targetPoints, timestamps, values, wasmReady]);

  const thresholdYCoord =
    thresholdY !== undefined
      ? height -
        padY -
        (Math.min(thresholdY, Math.max(maxY, 1)) / Math.max(maxY, 1)) *
          (height - padY * 2)
      : null;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="w-full h-[52px] overflow-visible"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0.01" />
        </linearGradient>
      </defs>

      {thresholdYCoord !== null && (
        <line
          x1={0}
          y1={thresholdYCoord}
          x2={width}
          y2={thresholdYCoord}
          stroke="rgba(244, 63, 94, 0.38)"
          strokeWidth="1"
          strokeDasharray="3 3"
        />
      )}

      {areaPath && <path d={areaPath} fill={`url(#${gradientId})`} />}
      {linePath && (
        <path
          d={linePath}
          fill="none"
          stroke={color}
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
      {lastPoint && (
        <circle
          cx={lastPoint.x}
          cy={lastPoint.y}
          r="2.75"
          fill={color}
        />
      )}
    </svg>
  );
}
