import React from 'react';
import { Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface ThreatForChart {
  severity: ThreatSeverity;
}

interface ThreatSeverityChartProps {
  threats: ThreatForChart[];
}

// Simple helper to count threats by severity
const countBySeverity = (threats: ThreatForChart[]) => {
  const severities: ThreatSeverity[] = ['low', 'medium', 'high', 'critical'];
  const counts: Record<ThreatSeverity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  for (const t of threats) {
    if (counts[t.severity] !== undefined) {
      counts[t.severity] += 1;
    }
  }

  return {
    labels: severities.map((s) => s.toUpperCase()),
    data: severities.map((s) => counts[s]),
  };
};

const ThreatSeverityChart: React.FC<ThreatSeverityChartProps> = ({ threats }) => {
  const { labels, data } = countBySeverity(threats);

  const chartData = {
    labels,
    datasets: [
      {
        label: 'Threats by Severity',
        data,
        backgroundColor: [
          'rgba(59, 130, 246, 0.3)', // low - blue
          'rgba(234, 179, 8, 0.3)',  // medium - yellow
          'rgba(248, 113, 113, 0.3)', // high - red
          'rgba(148, 27, 12, 0.5)',  // critical - dark red
        ],
        borderColor: [
          'rgba(59, 130, 246, 1)',
          'rgba(234, 179, 8, 1)',
          'rgba(248, 113, 113, 1)',
          'rgba(148, 27, 12, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

  return (
    <div style={{ width: '100%', maxWidth: 420 }}>
      <h3 style={{
        marginBottom: '0.75rem',
        fontSize: '1rem',
        fontWeight: 600,
      }}>
        Threats by Severity
      </h3>
      <Pie data={chartData} />
    </div>
  );
};

export default ThreatSeverityChart;
