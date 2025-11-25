import React from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

export interface ThreatsOverTimeChartProps {
  threats: Array<{
    id: string;
    timestamp: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
}

// Bucket threats by minute ("HH:MM") for a simple time-series view
const bucketThreatsByMinute = (threats: ThreatsOverTimeChartProps['threats']) => {
  const buckets: Record<string, number> = {};

  for (const t of threats) {
    const d = new Date(t.timestamp);
    if (isNaN(d.getTime())) continue;
    const label = d.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
    });
    buckets[label] = (buckets[label] || 0) + 1;
  }

  const labels = Object.keys(buckets).sort((a, b) => {
    // Sort by time using Date objects on todays date
    const today = new Date();
    const parse = (s: string) => {
      const [h, m] = s.split(':');
      const dt = new Date(today);
      dt.setHours(parseInt(h, 10), parseInt(m, 10), 0, 0);
      return dt.getTime();
    };
    return parse(a) - parse(b);
  });

  const data = labels.map((l) => buckets[l]);
  return { labels, data };
};

const ThreatsOverTimeChart: React.FC<ThreatsOverTimeChartProps> = ({ threats }) => {
  const { labels, data } = bucketThreatsByMinute(threats);

  const chartData = {
    labels,
    datasets: [
      {
        label: 'Threats over time',
        data,
        fill: false,
        borderColor: 'rgba(34, 197, 94, 1)',
        backgroundColor: 'rgba(34, 197, 94, 0.4)',
        tension: 0.25,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        display: false,
      },
    },
    scales: {
      x: {
        title: {
          display: true,
          text: 'Time (by minute)',
        },
      },
      y: {
        beginAtZero: true,
        title: {
          display: true,
          text: 'Number of threats',
        },
        precision: 0 as number | undefined,
      },
    },
  } as const;

  return (
    <div style={{ width: '100%', maxWidth: 720 }}>
      <h3
        style={{
          marginBottom: '0.75rem',
          fontSize: '1rem',
          fontWeight: 600,
        }}
      >
        Threats Over Time
      </h3>
      {labels.length === 0 ? (
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
          No threat data available.
        </p>
      ) : (
        <Line data={chartData} options={options} />
      )}
    </div>
  );
};

export default ThreatsOverTimeChart;
