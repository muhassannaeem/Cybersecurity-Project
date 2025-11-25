import React from 'react';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

export interface AttackFrequencyBarChartProps {
  threats: Array<{
    threatType: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
}

const AttackFrequencyBarChart: React.FC<AttackFrequencyBarChartProps> = ({ threats }) => {
  const countsByType: Record<string, number> = {};

  for (const t of threats) {
    const key = t.threatType || 'Unknown';
    countsByType[key] = (countsByType[key] || 0) + 1;
  }

  const labels = Object.keys(countsByType);
  const data = Object.values(countsByType);

  const chartData = {
    labels,
    datasets: [
      {
        label: 'Attack frequency by type',
        data,
        backgroundColor: 'rgba(59, 130, 246, 0.4)',
        borderColor: 'rgba(59, 130, 246, 1)',
        borderWidth: 1,
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
        ticks: {
          maxRotation: 45,
          minRotation: 0,
        },
      },
      y: {
        beginAtZero: true,
        precision: 0 as number | undefined,
      },
    },
  } as const;

  return (
    <div style={{ width: '100%', maxWidth: 520 }}>
      <h3
        style={{
          marginBottom: '0.75rem',
          fontSize: '1rem',
          fontWeight: 600,
        }}
      >
        Attack Frequency by Type
      </h3>
      {labels.length === 0 ? (
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
          No threat data available.
        </p>
      ) : (
        <Bar data={chartData} options={options} />
      )}
    </div>
  );
};

export default AttackFrequencyBarChart;
