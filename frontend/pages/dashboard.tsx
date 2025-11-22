import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from 'react-query';
import { Shield, Activity, Eye, Target, AlertTriangle, BarChart3, LogOut } from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { useRouter } from 'next/router';
import { isAuthenticated, logout } from '../utils/auth';
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

// Main component
export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const router = useRouter();

  // Check authentication status
  useEffect(() => {
    // Check if user is authenticated
    if (!isAuthenticated()) {
      router.push('/login');
    }
  }, []);

  const handleLogout = () => {
    logout();
    router.push('/login');
  };

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

  const handleApiAction = async (action: Promise<any>, messages: { loading: string; success: string; error: string; }) => {
    toast.promise(action, {
      loading: messages.loading,
      success: <b>{messages.success}</b>,
      error: <b>{messages.error}</b>,
    });
  };

  const queryClient = useQueryClient();

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
    { id: 'threats', name: 'Threats', icon: AlertTriangle },
    { id: 'decoys', name: 'Decoys', icon: Target },
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
            <button onClick={handleRunAnalysis} className={styles.btnSecondary}>Run Analysis</button>
            <button onClick={handleDeployDecoy} className={styles.btnPrimary} aria-label="Deploy Decoy">Deploy Decoy</button>
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

        {activeTab === 'decoys' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.tableCard}>
              <h3 className={styles.tableHeader}>Deployed Decoys</h3>
              <div className={styles.tableContainer}>
                <table className={styles.table}>
                  <thead>
                    <tr><th>Name</th><th>Type</th><th>Status</th><th>Port</th><th>IP Address</th><th>Created</th></tr>
                  </thead>
                  <tbody>
                    {decoysLoading ? (
                      <tr><td colSpan={6} style={{ textAlign: 'center' }}>Loading decoys...</td></tr>
                    ) : decoys && decoys.length > 0 ? (
                      decoys.map((decoy: any) => (
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

        {activeTab === 'monitoring' && (
          <div className={`${styles.contentWrapper} fadeInSlideUp`}>
            <div className={styles.tableCard}>
              <h3 className={styles.tableHeader}>System Alerts</h3>
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