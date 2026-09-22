import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { TrendPoint } from '../api/types'

interface TrendChartProps {
  data: TrendPoint[]
}

export function TrendChart({ data }: TrendChartProps) {
  const chartData = data.map((p) => ({
    ...p,
    label: p.day.slice(5),
  }))

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="openGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#e85d4c" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#e85d4c" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="resolvedGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#1ec8b2" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#1ec8b2" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(122,143,163,0.12)" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: '#7a8fa3', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: '#7a8fa3', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
            axisLine={false}
            tickLine={false}
            width={36}
          />
          <Tooltip
            contentStyle={{
              background: '#151e28',
              border: '1px solid #2a3848',
              borderRadius: 8,
              fontSize: 12,
              fontFamily: 'IBM Plex Mono',
            }}
            labelStyle={{ color: '#a8b8c8' }}
          />
          <Legend
            wrapperStyle={{ fontSize: 12, fontFamily: 'Sora', paddingTop: 8 }}
          />
          <Area
            type="monotone"
            dataKey="open_count"
            name="Open"
            stroke="#e85d4c"
            fill="url(#openGrad)"
            strokeWidth={2}
          />
          <Area
            type="monotone"
            dataKey="resolved_count"
            name="Resolved"
            stroke="#1ec8b2"
            fill="url(#resolvedGrad)"
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
