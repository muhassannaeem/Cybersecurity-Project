import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from 'react-query';
import { Shield, Activity, Eye, Target, AlertTriangle, BarChart3, LogOut } from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { useRouter } from 'next/router';
import { isAuthenticated, logout, getUser } from '../utils/auth';
import ThreatSeverityChart from '../components/ThreatSeverityChart';
import AttackFrequencyBarChart from '../components/AttackFrequencyBarChart';
import ThreatsOverTimeChart from '../components/ThreatsOverTimeChart';
import getSocket from '../utils/socket';
import styles from './Dashboard.module.css'; // Import the new CSS module

// Interfaces remain the same
interface DashboardStats {
  totalAlerts: number;
  activeThreats: number;
  decoysDeployed: number;
  detectionRate: number;
  falsePositives: number;
  responseTime: number;
}

interface ThreatData {
  id: string;
  timestamp: string;
  source: string;
  destination: string;
  threatType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'active' | 'resolved' | 'investigating';
}

interface MetricsSummary {
  stats?: DashboardStats;
  threats_summary?: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
  };
  alerts_summary?: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
  };
  anomalies_summary?: {
    total: number;
    by_severity: Record<string, number>;
    by_type: Record<string, number>;
  };
  threats_over_time?: {
    labels: string[];
    values: number[];
  };
  anomalies_over_time?: {
    labels: string[];
    values: number[];
  };
  // MITRE ATT&CK technique aggregates keyed by technique ID
  attack_patterns?: Record<string, { name: string; count: number }>;
}

// Main component
export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedThreat, setSelectedThreat] = useState<ThreatData | null>(null);
  const [decoyFilter, setDecoyFilter] = useState<string>('all');
  const [currentUser, setCurrentUser] = useState<any | null>(null);
  const router = useRouter();

  // Check authentication status
  useEffect(() => {
    if (!isAuthenticated()) {
      router.push('/login');
      return;
    }
    // Load user (including role) from localStorage-backed session
    const user = getUser();
    if (user) {
      setCurrentUser(user);
    }
  }, []);

  const handleLogout = () => {
    logout();
    router.push('/login');
  };

  const canManageSensitiveActions = currentUser && ['admin', 'analyst'].includes(currentUser.role);

  // Real API calls to backend
  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>('dashboard-stats',
    async () => {
      const response = await axios.get('/api/dashboard/stats');
      return response.data;
    }, { refetchInterval: 30000 }
  );

  const { data: threats, isLoading: threatsLoading } = useQuery<ThreatData[]>('recent-threats',
    async () => {
      const response = await axios.get('/api/threats/recent');
      return response.data;
    }, { refetchInterval: 10000 }
  );

  // Fetch decoys data
  const { data: decoys, isLoading: decoysLoading } = useQuery('decoys',
    async () => {
      const response = await axios.get('/api/decoys');
      return response.data;
    }, { refetchInterval: 15000 }
  );

// Fetch alerts data
  const { data: alerts, isLoading: alertsLoading } = useQuery('alerts',
    async () => {
      const response = await axios.get('/api/alerts');
      return response.data;
    }, { refetchInterval: 20000 }
  );

  // Fetch traffic anomalies (for anomalies tab)
  const { data: anomalies } = useQuery('recent-anomalies',
    async () => {
      const response = await axios.get('/api/anomalies/recent');
      return response.data;
    }, { refetchInterval: 30000 }
  );

  // Fetch aggregate metrics (analytics tab)
  const { data: metrics } = useQuery<MetricsSummary>('metrics-summary',
    async () => {
      const response = await axios.get('/api/metrics/summary');
      return response.data;
    }, { refetchInterval: 30000 }
  );

  const handleApiAction = async (action: Promise<any>, messages: { loading: string; success: string; error: string; }) => {
    toast.promise(action, {
      loading: messages.loading,
      success: <b>{messages.success}</b>,
      error: <b>{messages.error}</b>,
    });
  };

  const queryClient = useQueryClient();

  // Real-time Socket.IO subscriptions
  useEffect(() => {
    const socket = getSocket();

    const handleStatsUpdate = (statsUpdate: DashboardStats) => {
      queryClient.setQueryData<DashboardStats | undefined>('dashboard-stats', (old) => ({
        ...(old || {} as DashboardStats),
        ...statsUpdate,
      }));
    };

    const handleThreatUpdate = (threatsUpdate: ThreatData[] | ThreatData) => {
      // Accept either a single threat or an array snapshot
      queryClient.setQueryData<ThreatData[] | undefined>('recent-threats', (old) => {
        if (Array.isArray(threatsUpdate)) {
          return threatsUpdate;
        }
        const existing = old || [];
        const filtered = existing.filter((t) => t.id !== threatsUpdate.id);
        return [threatsUpdate, ...filtered].slice(0, 100);
      });
    };

    const handleDecoyUpdate = (decoysUpdate: any[] | any) => {
      queryClient.setQueryData<any[] | undefined>('decoys', (old) => {
        if (Array.isArray(decoysUpdate)) {
          return decoysUpdate;
        }
        const existing = old || [];
        const filtered = existing.filter((d) => d.id !== decoysUpdate.id);
        return [decoysUpdate, ...filtered];
      });
    };

    const handleAlertUpdate = (alertsUpdate: any[] | any) => {
      queryClient.setQueryData<any[] | undefined>('alerts', (old) => {
        if (Array.isArray(alertsUpdate)) {
          return alertsUpdate;
        }
        const existing = old || [];
        const filtered = existing.filter((a) => a.id !== alertsUpdate.id);
        return [alertsUpdate, ...filtered].slice(0, 200);
      });
    };

    const handleTrafficAnomalyUpdate = (anomaliesUpdate: any[] | any) => {
      queryClient.setQueryData<any[] | undefined>('recent-anomalies', (old) => {
        if (Array.isArray(anomaliesUpdate)) {
          return anomaliesUpdate;
        }
        const existing = old || [];
        const filtered = existing.filter((a) => a.id !== anomaliesUpdate.id);
        return [anomaliesUpdate, ...filtered].slice(0, 200);
      });
    };

    socket.on('stats_update', handleStatsUpdate);
    socket.on('threat_update', handleThreatUpdate);
    socket.on('decoy_update', handleDecoyUpdate);
    socket.on('alert_update', handleAlertUpdate);
    socket.on('traffic_anomaly', handleTrafficAnomalyUpdate);

    return () => {
      socket.off('stats_update', handleStatsUpdate);
      socket.off('threat_update', handleThreatUpdate);
      socket.off('decoy_update', handleDecoyUpdate);
      socket.off('alert_update', handleAlertUpdate);
      socket.off('traffic_anomaly', handleTrafficAnomalyUpdate);
    };
  }, [queryClient]);

  const handleDeployDecoy = () => handleApiAction(
    axios.post('/api/decoys/deploy', { type: 'web_server' }).then(() => {
      // Refresh dashboard stats after deploying decoy
      queryClient.invalidateQueries('dashboard-stats');
    }), { loading: 'Deploying decoy...', success: 'Decoy deployed!', error: 'Failed to deploy decoy.' }
  );

  const handleRunAnalysis = () => handleApiAction(
    axios.post('/api/analysis/run', { type: 'full' }).then(() => {
      // Refresh dashboard stats after running analysis
      queryClient.invalidateQueries('dashboard-stats');
    }), { loading: 'Starting analysis...', success: 'Analysis started!', error: 'Failed to start analysis.' }
  );

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'critical': return styles.severityCritical;
      case 'high': return styles.severityHigh;
      case 'medium': return styles.severityMedium;
      case 'low': return styles.severityLow;
      default: return '';
    }
  };
  
  const statCardsData = [
    { title: 'Total Alerts', dataKey: 'totalAlerts', icon: AlertTriangle, color: 'var(--color-danger)' },
    { title: 'Active Threats', dataKey: 'activeThreats', icon: Target, color: 'var(--color-warning)' },
    { title: 'Decoys Deployed', dataKey: 'decoysDeployed', icon: Eye, color: 'var(--color-success)' },
    { title: 'Detection Rate', dataKey: 'detectionRate', icon: Activity, color: 'var(--color-primary)', unit: '%' },
    { title: 'False Positives', dataKey: 'falsePositives', icon: BarChart3, color: 'var(--text-secondary)' },
    { title: 'Response Time', dataKey: 'responseTime', icon: Shield, color: 'var(--color-success)', unit: 'ms' },
  ];

  const tabs = [
    { id: 'overview', name: 'Overview', icon: BarChart3 },
    { id: 'analytics', name: 'Analytics', icon: Activity },
    { id: 'threats', name: 'Threats', icon: AlertTriangle },
    { id: 'decoys', name: 'Decoys', icon: Target },
    { id: 'anomalies', name: 'Anomalies', icon: Eye },
    { id: 'analysis', name: 'Analysis', icon: Activity },
    { id: 'monitoring', name: 'Monitoring', icon: Eye },
  ];

  return (
    <div className={styles.wrapper}>
      <header className={`${styles.header} glass`}>
        <div className={`${styles.maxWidthWrapper} ${styles.headerContent}`}>
          <div className={styles.headerTitle}>
            <Shield className={styles.headerIcon} />
            <h1>Cybersecurity System</h1>
          </div>
          <div className={styles.headerActions}>
            {canManageSensitiveActions && (
              <button onClick={handleRunAnalysis} className={styles.btnSecondary}>Run Analysis</button>
            )}
            {canManageSensitiveActions && (
              <button onClick={handleDeployDecoy} className={styles.btnPrimary} aria-label="Deploy Decoy">Deploy Decoy</button>
            )}
            <button onClick={handleLogout} className={styles.btnSecondary} aria-label="Logout" style={{ display: 'flex', alignItems: 'center' }}>
              <LogOut size={18} style={{ marginRight: '0.5rem' }} />
              Logout
            </button>
          </div>
        </div>
      </header>

      <nav className={`${styles.nav} glass`} aria-label="Main navigation">
        <div className={styles.maxWidthWrapper}>
          <div className={styles.navTabs}>
            {tabs.map((tab) => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)} className={`${styles.tab} ${activeTab === tab.id ? styles.tabActive : ''}`}>
                <tab.icon />
                {tab.name}
              </button>
            ))}
          </div>
        </div>
      </nav>

      <main className={`${styles.main} ${styles.maxWidthWrapper}`}>
        {activeTab === 'overview' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.statsGrid}>
              {statCardsData.map(({ title, dataKey, icon: Icon, color, unit = '' }) => {
                const value = stats?.[dataKey as keyof DashboardStats];
                return (
                  <div key={title} className={`${styles.statCard} glass-bg`}>
                    <div className={styles.statIconWrapper}><Icon style={{ color: color, height: '100%', width: '100%' }} /></div>
                    <dl className={styles.statText}>
                      <dt>{title}</dt>
                      <dd>{statsLoading ? '...' : `${value ?? '0'}${unit}`}</dd>
                    </dl>
                  </div>
                );
              })}
            </div>

            {/* Charts row */}
            <div className={styles.chartsGrid}>
              <div className={`${styles.card} glass-bg`}>
                <ThreatSeverityChart threats={threats || []} />
              </div>
              <div className={`${styles.card} glass-bg`}>
                <AttackFrequencyBarChart threats={threats || []} />
              </div>
            </div>

            {/* Time-series row */}
            <div className={styles.fullWidthSection}>
              <div className={`${styles.card} glass-bg`}>
                <ThreatsOverTimeChart threats={threats || []} />
              </div>
            </div>

            <div className={`${styles.tableCard} glass-bg`}>
              <h3 className={styles.tableHeader}>Recent Threats</h3>
              <div className={styles.tableContainer}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>Time</th><th>Source</th><th>Destination</th><th>Type</th><th>Severity</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {threatsLoading ? (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>Loading threats...</td></tr>
                    ) : threats && threats.length > 0 ? (
                      threats.map((threat) => (
                        <tr key={threat.id}>
                          <td>{new Date(threat.timestamp).toLocaleString()}</td>
                          <td style={{ fontFamily: 'var(--font-family-mono)' }}>{threat.source}</td>
                          <td style={{ fontFamily: 'var(--font-family-mono)' }}>{threat.destination}</td>
                          <td>{threat.threatType}</td>
                          <td><span className={`${styles.severityPill} ${getSeverityClass(threat.severity)}`}>{threat.severity}</span></td>
                          <td style={{ textTransform: 'capitalize' }}>{threat.status}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>No threats detected</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
        
        {activeTab === 'threats' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.tableCard}>
              <h3 className={styles.tableHeader}>All Threats</h3>
              <div className={styles.tableContainer}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>Time</th><th>Source</th><th>Destination</th><th>Type</th><th>Severity</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {threatsLoading ? (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>Loading threats...</td></tr>
                    ) : threats && threats.length > 0 ? (
                      threats.map((threat) => (
                        <tr
                          key={threat.id}
                          onClick={() => setSelectedThreat(threat)}
                          style={{ cursor: 'pointer', backgroundColor: selectedThreat?.id === threat.id ? 'rgba(79,70,229,0.06)' : undefined }}
                        >
                          <td>{new Date(threat.timestamp).toLocaleString()}</td>
                          <td style={{ fontFamily: 'var(--font-family-mono)' }}>{threat.source}</td>
                          <td style={{ fontFamily: 'var(--font-family-mono)' }}>{threat.destination}</td>
                          <td>{threat.threatType}</td>
                          <td><span className={`${styles.severityPill} ${getSeverityClass(threat.severity)}`}>{threat.severity}</span></td>
                          <td style={{ textTransform: 'capitalize' }}>{threat.status}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>No threats detected</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {selectedThreat && (
              <div className={`${styles.card} glass-bg`}>
                <h3 style={{ marginTop: 0, marginBottom: '0.75rem' }}>Attribution (Mock)</h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                  This is a frontend-only preview of how attribution details could look. Values are mocked based on the selected threat type.
                </p>
                <dl style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: '0.75rem', fontSize: '0.875rem' }}>
                  <div>
                    <dt style={{ fontWeight: 600 }}>Threat Type</dt>
                    <dd style={{ margin: 0 }}>{selectedThreat.threatType}</dd>
                  </div>
                  <div>
                    <dt style={{ fontWeight: 600 }}>Likely Technique</dt>
                    <dd style={{ margin: 0 }}>{selectedThreat.threatType.includes('SQL') ? 'T1005 - Data from Local System' : selectedThreat.threatType.includes('DDoS') ? 'T1498 - Network Denial of Service' : 'T1001 - Data Obfuscation'}</dd>
                  </div>
                  <div>
                    <dt style={{ fontWeight: 600 }}>Mock Threat Actor</dt>
                    <dd style={{ margin: 0 }}>{selectedThreat.severity === 'critical' ? 'APT28 (High Confidence)' : 'Generic Threat Group (Medium Confidence)'}</dd>
                  </div>
                </dl>
              </div>
            )}
          </div>
        )}

        {activeTab === 'decoys' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.tableCard}>
              <h3 className={styles.tableHeader}>Deployed Decoys</h3>

              {/* Decoy filters & summary */}
              <div style={{ padding: '0 1.5rem 1rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {['all', 'web_server', 'ssh', 'database', 'file_share', 'dionaea', 'conpot'].map((type) => (
                    <button
                      key={type}
                      onClick={() => setDecoyFilter(type)}
                      className={decoyFilter === type ? styles.btnPrimary : styles.btnSecondary}
                      style={{ fontSize: '0.75rem', padding: '0.25rem 0.75rem' }}
                    >
                      {type === 'all' ? 'All' : type.replace('_', ' ')}
                    </button>
                  ))}
                </div>

                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  {(() => {
                    const list = (decoys || []) as any[];
                    const total = list.length;
                    const byType: Record<string, number> = {};
                    list.forEach((d) => {
                      byType[d.type] = (byType[d.type] || 0) + 1;
                    });
                    const parts = Object.entries(byType).map(([t, c]) => `${t} (${c})`);
                    return `Total: ${total}${parts.length ? '  ' + parts.join(' | ') : ''}`;
                  })()}
                </div>
              </div>

              <div className={styles.tableContainer}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>Name</th><th>Type</th><th>Status</th><th>Port</th><th>IP Address</th><th>Created</th></tr>
                  </thead>
                  <tbody>
                    {decoysLoading ? (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>Loading decoys...</td></tr>
                    ) : decoys && decoys.length > 0 ? (
                      (decoys as any[])
                        .filter((decoy: any) => decoyFilter === 'all' || decoy.type === decoyFilter)
                        .map((decoy: any) => (
                          <tr key={decoy.id}>
                            <td>{decoy.name}</td>
                            <td style={{ textTransform: 'capitalize' }}>{decoy.type.replace('_', ' ')}</td>
                            <td><span className={`${styles.severityPill} ${decoy.status === 'active' ? styles.severityLow : decoy.status === 'compromised' ? styles.severityCritical : styles.severityMedium}`}>{decoy.status}</span></td>
                            <td style={{ fontFamily: 'var(--font-family-mono)' }}>{decoy.port}</td>
                            <td style={{ fontFamily: 'var(--font-family-mono)' }}>{decoy.ip_address}</td>
                            <td>{new Date(decoy.created_at).toLocaleString()}</td>
                          </tr>
                        ))
                    ) : (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>No decoys deployed</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'anomalies' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.tableCard}>
              <h3 className={styles.tableHeader}>Traffic Anomalies</h3>
              <div className={styles.tableContainer}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>Time</th><th>Source</th><th>Destination</th><th>Type</th><th>Severity</th><th>Description</th></tr>
                  </thead>
                  <tbody>
                    {!anomalies ? (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>Loading anomalies...</td></tr>
                    ) : anomalies.length > 0 ? (
                      (anomalies as any[]).map((a: any) => (
                        <tr key={a.id}>
                          <td>{new Date(a.timestamp).toLocaleString()}</td>
                          <td style={{ fontFamily: 'var(--font-family-mono)' }}>{a.source}</td>
                          <td style={{ fontFamily: 'var(--font-family-mono)' }}>{a.destination}</td>
                          <td style={{ textTransform: 'capitalize' }}>{a.type.replace('_', ' ')}</td>
                          <td><span className={`${styles.severityPill} ${getSeverityClass(a.severity)}`}>{a.severity}</span></td>
                          <td>{a.description}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>No anomalies</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'analysis' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.tableCard}>
              <h3 className={styles.tableHeader}>Analysis Status</h3>
              <div className={styles.tableContainer}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>Analysis ID</th><th>Type</th><th>Status</th><th>Started</th><th>Actions</th></tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>analysis_3275</td>
                      <td>Full System</td>
                      <td><span className={`${styles.severityPill} ${styles.severityLow}`}>Running</span></td>
                      <td>{new Date().toLocaleString()}</td>
                      <td>
                        <button className={styles.btnSecondary} style={{ fontSize: '0.8rem', padding: '0.25rem 0.5rem' }}>View Details</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.card}>
              <h3 style={{ marginTop: 0, marginBottom: '0.75rem' }}>Analytics Overview</h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                This tab shows a frontend-first preview of metrics using the `/api/metrics/summary` endpoint (currently backed by mock, stateful data).
              </p>

              <div className={styles.statsGrid}>
                <div className={`${styles.statCard} glass-bg`}>
                  <dl className={styles.statText}>
                    <dt>Total Threats (cached)</dt>
                    <dd>{metrics?.threats_summary?.total ?? 0}</dd>
                  </dl>
                </div>
                <div className={`${styles.statCard} glass-bg`}>
                  <dl className={styles.statText}>
                    <dt>Total Alerts (cached)</dt>
                    <dd>{metrics?.alerts_summary?.total ?? 0}</dd>
                  </dl>
                </div>
                <div className={`${styles.statCard} glass-bg`}>
                  <dl className={styles.statText}>
                    <dt>Total Anomalies (cached)</dt>
                    <dd>{metrics?.anomalies_summary?.total ?? 0}</dd>
                  </dl>
                </div>
                <div className={`${styles.statCard} glass-bg`}>
                  <dl className={styles.statText}>
                    <dt>ATT&CK Techniques (distinct)</dt>
                    <dd>{metrics?.attack_patterns ? Object.keys(metrics.attack_patterns).length : 0}</dd>
                  </dl>
                </div>
              </div>

              {metrics?.attack_patterns && (
                <div style={{ marginTop: '1.5rem' }}>
                  <h4 style={{ margin: 0, marginBottom: '0.5rem', fontSize: '0.95rem' }}>Top MITRE ATT&CK Techniques</h4>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                    Based on current threats, anomalies, and alerts enriched via the threat attribution module.
                  </p>
                  <table className={styles.table}>
                    <thead>
                      <tr>
                        <th style={{ width: '20%' }}>Technique ID</th>
                        <th style={{ width: '50%' }}>Name</th>
                        <th style={{ width: '30%' }}>Relative Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(metrics.attack_patterns)
                        .sort(([, a], [, b]) => (b.count ?? 0) - (a.count ?? 0))
                        .slice(0, 8)
                        .map(([id, info]) => (
                          <tr key={id}>
                            <td style={{ fontFamily: 'var(--font-family-mono)' }}>{id}</td>
                            <td>{info.name}</td>
                            <td>{info.count}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'monitoring' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.tableCard}>
              <h3 className={styles.tableHeader}>System Alerts</h3>

              {/* Alerts summary widgets */}
              <div style={{ padding: '0 1.5rem 1rem' }}>
                {alerts && alerts.length > 0 && (
                  <div className={styles.statsGrid}>
                    {(() => {
                      const list = alerts as any[];
                      const byStatus: Record<string, number> = {};
                      list.forEach((a) => {
                        byStatus[a.status] = (byStatus[a.status] || 0) + 1;
                      });
                      const order = ['new', 'acknowledged', 'resolved'];
                      return order.map((status) => (
                        <div key={status} className={`${styles.statCard} glass-bg`}>
                          <dl className={styles.statText}>
                            <dt style={{ textTransform: 'capitalize' }}>{status}</dt>
                            <dd>{byStatus[status] || 0}</dd>
                          </dl>
                        </div>
                      ));
                    })()}
                  </div>
                )}
              </div>

              <div className={styles.tableContainer}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>Time</th><th>Type</th><th>Severity</th><th>Message</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {alertsLoading ? (
                      <tr><td colSpan={5} style={{ textAlign: 'center' }}>Loading alerts...</td></tr>
                    ) : alerts && alerts.length > 0 ? (
                      alerts.map((alert: any) => (
                        <tr key={alert.id}>
                          <td>{new Date(alert.timestamp).toLocaleString()}</td>
                          <td style={{ textTransform: 'capitalize' }}>{alert.type.replace('_', ' ')}</td>
                          <td><span className={`${styles.severityPill} ${getSeverityClass(alert.severity)}`}>{alert.severity}</span></td>
                          <td>{alert.message}</td>
                          <td style={{ textTransform: 'capitalize' }}>{alert.status}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={5} style={{ textAlign: 'center' }}>No alerts</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}