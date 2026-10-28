import React, { useState, useEffect, useCallback } from 'react';
import {
    PieChart, Pie, Cell, Tooltip, Legend,
    BarChart, Bar, XAxis, YAxis, CartesianGrid,
    AreaChart, Area,
    ResponsiveContainer,
} from 'recharts';
import { fetchDashboard, refreshComponentCount } from '../api/client';
import api from '../api/client';

// ─── Color Palettes ────────────────────────────────────

const RISK_COLORS = {
    Low: '#22c55e',
    Moderate: '#eab308',
    High: '#f97316',
    'Very High': '#ef4444',
    Critical: '#dc2626',
};

const CRITICALITY_COLORS = {
    low: '#22c55e',
    medium: '#3b82f6',
    high: '#f97316',
    critical: '#ef4444',
};

const ENV_COLORS = {
    development: '#a855f7',
    staging: '#eab308',
    production: '#ef4444',
};

const SEVERITY_COLORS = {
    critical: '#dc2626',
    high: '#ef4444',
    medium: '#f97316',
    low: '#22c55e',
    unknown: '#64748b',
};

const CHART_COLORS = [
    '#3b82f6', '#22c55e', '#f97316',
    '#ef4444', '#a855f7', '#eab308',
    '#06b6d4', '#ec4899',
];

// ─── Custom Tooltip ────────────────────────────────────

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload || !payload.length) return null;
    return (
        <div style={{
            background: '#1e293b',
            border: '1px solid #334155',
            borderRadius: 8,
            padding: '10px 14px',
            color: '#f1f5f9',
            fontSize: 13,
        }}>
            {label && (
                <p style={{ marginBottom: 4, fontWeight: 600 }}>
                    {label}
                </p>
            )}
            {payload.map((entry, i) => (
                <p key={i} style={{ color: entry.color, margin: 0 }}>
                    {entry.name}: {entry.value}
                </p>
            ))}
        </div>
    );
};

// ─── Donut Chart Component ─────────────────────────────

function DonutChart({ title, data, colorMap }) {
    const filtered = data.filter((d) => d.value > 0);

    if (!filtered.length) {
        return (
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>{title}</h2>
                <div style={{
                    textAlign: 'center',
                    padding: 40,
                    color: '#606060',
                }}>
                    No data available yet.
                </div>
            </div>
        );
    }

    return (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>{title}</h2>
            <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                    <Pie
                        data={filtered}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={95}
                        paddingAngle={3}
                        dataKey="value"
                        label={({ name, value }) =>
                            `${name}: ${value}`
                        }
                    >
                        {filtered.map((entry, i) => (
                            <Cell
                                key={i}
                                fill={
                                    colorMap?.[entry.name]
                                    || CHART_COLORS[
                                        i % CHART_COLORS.length
                                    ]
                                }
                            />
                        ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                    <Legend
                        wrapperStyle={{ fontSize: 12 }}
                    />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
}

// ─── Bar Chart Component ───────────────────────────────

function HorizontalBarChart({ title, data, colorMap }) {
    if (!data || !data.length) {
        return (
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>{title}</h2>
                <div style={{
                    textAlign: 'center',
                    padding: 40,
                    color: '#606060',
                }}>
                    No data available.
                </div>
            </div>
        );
    }

    return (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>{title}</h2>
            <ResponsiveContainer width="100%" height={280}>
                <BarChart data={data} layout="vertical">
                    <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="#E5E5E5"
                        horizontal={false}
                    />
                    <XAxis
                        type="number"
                        stroke="#606060"
                        fontSize={12}
                    />
                    <YAxis
                        type="category"
                        dataKey="name"
                        stroke="#606060"
                        fontSize={12}
                        width={100}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                        {data.map((entry, i) => (
                            <Cell
                                key={i}
                                fill={
                                    colorMap?.[
                                        entry.name.toLowerCase()
                                    ]
                                    || CHART_COLORS[
                                        i % CHART_COLORS.length
                                    ]
                                }
                            />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}

// ─── Risk Trend Chart ──────────────────────────────────

function RiskTrendChart({ data }) {
    if (!data || !data.length) {
        return (
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>
                    Risk Score Trend
                </h2>
                <div style={{
                    textAlign: 'center',
                    padding: 40,
                    color: '#606060',
                }}>
                    Not enough data for trend analysis.
                    Calculate risk scores over multiple days.
                </div>
            </div>
        );
    }

    return (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>Risk Score Trend</h2>
            <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={data}>
                    <defs>
                        <linearGradient
                            id="riskGrad"
                            x1="0" y1="0" x2="0" y2="1"
                        >
                            <stop
                                offset="5%"
                                stopColor="#0076CE"
                                stopOpacity={0.3}
                            />
                            <stop
                                offset="95%"
                                stopColor="#0076CE"
                                stopOpacity={0}
                            />
                        </linearGradient>
                    </defs>
                    <CartesianGrid
                        strokeDasharray="3 3"
                        stroke="#E5E5E5"
                    />
                    <XAxis
                        dataKey="date"
                        stroke="#606060"
                        fontSize={11}
                    />
                    <YAxis
                        stroke="#606060"
                        fontSize={11}
                        domain={[0, 10]}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Area
                        type="monotone"
                        dataKey="score"
                        stroke="#0076CE"
                        fillOpacity={1}
                        fill="url(#riskGrad)"
                        strokeWidth={2}
                        name="Avg Risk Score"
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
}

// ─── KPI Card ──────────────────────────────────────────

function KpiCard({ label, value, subtitle, variant }) {
    const colorClass = variant || 'info';
    const borderColor = variant === 'critical' ? '#D13438' : variant === 'warning' ? '#F4B400' : variant === 'success' ? '#107C10' : '#0076CE';
    
    return (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)', borderTop: `3px solid ${borderColor}` }}>
            <div style={{ fontSize: '13px', color: '#606060', marginBottom: '8px' }}>{label}</div>
            <div style={{ fontSize: '32px', fontWeight: 600, color: '#202020' }}>{value}</div>
            {subtitle && (
                <div style={{ fontSize: '12px', color: '#606060', marginTop: '4px' }}>{subtitle}</div>
            )}
        </div>
    );
}

// ─── Recent Apps Table ─────────────────────────────────

function RecentAppsTable({ apps }) {
    if (!apps || !apps.length) {
        return (
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>
                    Recent Applications
                </h2>
                <div style={{
                    textAlign: 'center',
                    padding: 40,
                    color: '#606060',
                }}>
                    No applications registered yet.
                </div>
            </div>
        );
    }

    return (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>
                Recent Applications
            </h2>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                    <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
                        <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Application</th>
                        <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Criticality</th>
                        <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Environment</th>
                        <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Internet</th>
                        <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {apps.slice(0, 10).map((app) => (
                        <tr key={app.id} style={{ borderBottom: '1px solid #E5E5E5' }}>
                            <td style={{ padding: '12px 16px', color: '#202020', fontWeight: 500 }}>
                                {app.name}
                            </td>
                            <td style={{ padding: '12px 16px' }}>
                                <span
                                    style={{
                                        padding: '2px 8px',
                                        borderRadius: '4px',
                                        fontSize: '12px',
                                        fontWeight: 500,
                                        backgroundColor: app.criticality === 'critical' ? '#FDE8E8' : app.criticality === 'high' ? '#FFF4E5' : '#E6F4EA',
                                        color: app.criticality === 'critical' ? '#D13438' : app.criticality === 'high' ? '#F4B400' : '#107C10'
                                    }}
                                >
                                    {app.criticality ? app.criticality.charAt(0).toUpperCase() + app.criticality.slice(1).toLowerCase() : 'Unknown'}
                                </span>
                            </td>
                            <td style={{ padding: '12px 16px', color: '#606060' }}>{app.environment}</td>
                            <td style={{ padding: '12px 16px', color: '#606060' }}>
                                {app.internet_facing ? 'Yes' : 'No'}
                            </td>
                            <td style={{ padding: '12px 16px', color: '#606060' }}>
                                {new Date(app.created_at).toLocaleDateString()}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

// ─── Remediation Progress ──────────────────────────────

function RemediationChart({ stats }) {
    if (!stats || stats.total === 0) {
        return (
            <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>
                    Remediation Progress
                </h2>
                <div style={{
                    textAlign: 'center',
                    padding: 40,
                    color: '#606060',
                }}>
                    No remediation tasks yet.
                </div>
            </div>
        );
    }

    const data = [
        { name: 'Open', value: stats.open || 0 },
        { name: 'In Progress', value: stats.in_progress || 0 },
        { name: 'Resolved', value: stats.resolved || 0 },
        { name: 'Mitigated', value: stats.mitigated || 0 },
        { name: 'Accepted', value: stats.risk_accepted || 0 },
    ].filter((d) => d.value > 0);

    const remColors = {
        Open: '#ef4444',
        'In Progress': '#f97316',
        Resolved: '#22c55e',
        Mitigated: '#3b82f6',
        Accepted: '#a855f7',
    };

    const pct = stats.total
        ? Math.round(
              ((stats.resolved + stats.mitigated)
              / stats.total) * 100
          )
        : 0;

    return (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>
                Remediation Progress ({pct}% resolved)
            </h2>
            <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={95}
                        paddingAngle={3}
                        dataKey="value"
                    >
                        {data.map((entry) => (
                            <Cell
                                key={entry.name}
                                fill={remColors[entry.name]}
                            />
                        ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
}

// ─── Main Dashboard Page ───────────────────────────────

export default function DashboardPage() {
    const [dashboard, setDashboard] = useState(null);
    const [riskScores, setRiskScores] = useState([]);
    const [remStats, setRemStats] = useState(null);
    const [apps, setApps] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [lastRefresh, setLastRefresh] = useState(null);

    const loadData = useCallback(async () => {
        try {
            setError(null);

            const [dashRes, appRes, compCountRes] = await Promise.all([
                api.get('/dashboard/'),
                api.get('/applications/'),
                refreshComponentCount(),
            ]);

            setDashboard(dashRes.data);
            setApps(appRes.data);

            // Update component count from fresh count
            if (compCountRes.data && compCountRes.data.total_components !== undefined) {
                setDashboard(prev => ({
                    ...prev,
                    summary: {
                        ...prev.summary,
                        total_components: compCountRes.data.total_components
                    }
                }));
            }

            // Try to load risk scores (may not exist)
            try {
                const rsRes = await api.get('/risk-scores/');
                setRiskScores(rsRes.data || []);
            } catch {
                setRiskScores([]);
            }

            // Try to load remediation stats
            try {
                const remRes = await api.get(
                    '/remediations/stats/summary'
                );
                setRemStats(remRes.data);
            } catch {
                setRemStats(null);
            }

            setLastRefresh(new Date());
        } catch (err) {
            console.error('Dashboard load error:', err);
            setError('Failed to load dashboard data.');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadData();
    }, [loadData]);

    // Auto-refresh every 60 seconds
    useEffect(() => {
        const interval = setInterval(loadData, 60000);
        return () => clearInterval(interval);
    }, [loadData]);

    // Refresh when page becomes visible (user navigates back)
    useEffect(() => {
        const handleVisibilityChange = () => {
            if (!document.hidden) {
                loadData();
            }
        };
        document.addEventListener('visibilitychange', handleVisibilityChange);
        return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
    }, [loadData]);

    if (loading) {
        return (
            <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: 400,
                color: '#606060',
            }}>
                Loading...
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: '40px', textAlign: 'center', color: '#D13438' }}>
                <p>{error}</p>
                <button
                    onClick={loadData}
                    style={{ 
                        backgroundColor: '#0076CE', 
                        color: '#FFFFFF', 
                        border: 'none', 
                        padding: '8px 16px', 
                        borderRadius: '6px', 
                        fontSize: '13px', 
                        fontWeight: 500, 
                        cursor: 'pointer',
                        marginTop: 12 
                    }}
                >
                    Retry
                </button>
            </div>
        );
    }

    const d = dashboard || {};
    const summary = d.summary || d;

    // Build chart data from dashboard response
    const critData = (
        d.criticality_distribution || []
    ).map((item) => ({
        name: item.label || item.name || item.criticality,
        value: item.value || item.count || 0,
    }));

    const envData = (
        d.environment_distribution || []
    ).map((item) => ({
        name: item.label || item.name || item.environment,
        value: item.value || item.count || 0,
    }));

    const compTypeData = (
        d.component_type_distribution || []
    ).map((item) => ({
        name: item.label || item.name || item.component_type,
        value: item.value || item.count || 0,
    }));

    // Risk distribution from risk scores
    const riskDist = {};
    riskScores.forEach((rs) => {
        const rating = rs.rating || 'Unknown';
        riskDist[rating] = (riskDist[rating] || 0) + 1;
    });
    const riskDistData = Object.entries(riskDist).map(
        ([name, value]) => ({ name, value })
    );

    // CVE severity from dashboard or direct
    const sevData = [];
    if (d.cve_severity_distribution) {
        d.cve_severity_distribution.forEach((item) => {
            sevData.push({
                name: item.label || item.severity,
                value: item.value || item.count || 0,
            });
        });
    }

    // Risk trend (from risk score history)
    const trendData = riskScores
        .filter((rs) => rs.calculated_at)
        .map((rs) => ({
            date: new Date(
                rs.calculated_at
            ).toLocaleDateString(),
            score: rs.overall_score || 0,
        }))
        .reverse();

    // KPI values
    const totalApps = summary.total_applications
        || summary.total_apps || apps.length || 0;
    const totalVendors = summary.total_vendors || 0;
    const totalComponents = summary.total_components || 0;
    const totalCves = summary.total_cves || 0;
    const criticalApps = summary.critical_applications
        || summary.critical_apps || 0;
    const internetFacing = summary.internet_facing_apps
        || summary.internet_facing || 0;

    return (
        <div>
          <div style={{ marginBottom: '32px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>
              Dashboard
            </h1>
            <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>
              Overview of third-party risk assessment metrics and security posture
            </p>
          </div>

          {/* Refresh bar */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 20,
          }}>
            <span style={{ fontSize: 12, color: '#606060' }}>
              {lastRefresh && (
                  <>
                    Last updated:{' '}
                    {lastRefresh.toLocaleTimeString()}
                    {' · Auto-refreshes every 60s'}
                  </>
              )}
            </span>
            <button
                onClick={loadData}
                style={{ 
                    backgroundColor: 'transparent', 
                    color: '#0076CE', 
                    border: '1px solid #0076CE', 
                    padding: '6px 12px', 
                    borderRadius: '4px', 
                    fontSize: '12px', 
                    cursor: 'pointer' 
                }}
            >
              ↻ Refresh
            </button>
          </div>

          {/* KPI Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '24px', marginBottom: '32px' }}>
            <KpiCard
                label="Applications"
                value={totalApps}
                subtitle="Registered"
                variant="info"
            />
            <KpiCard
                label="Vendors"
                value={totalVendors}
                subtitle="Third-party"
                variant="info"
            />
            <KpiCard
                label="Components"
                value={totalComponents}
                subtitle="Libraries"
                variant="info"
            />
            <KpiCard
                label="CVEs"
                value={totalCves}
                subtitle="Vulnerabilities"
                variant={totalCves > 0 ? 'warning' : 'success'}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '24px', marginBottom: '32px' }}>
            <KpiCard
                label="Critical Apps"
                value={criticalApps}
                subtitle="Immediate attention"
                variant={
                    criticalApps > 0 ? 'critical' : 'success'
                }
            />
            <KpiCard
                label="Internet Facing"
                value={internetFacing}
                subtitle="Exposed apps"
                variant={
                    internetFacing > 0 ? 'warning' : 'success'
                }
            />
          </div>

          {/* Row 1: Risk Distribution + Criticality */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '32px' }}>
            <DonutChart
                title="Risk Distribution"
                data={riskDistData}
                colorMap={RISK_COLORS}
            />
            <HorizontalBarChart
                title="Business Criticality"
                data={critData}
                colorMap={CRITICALITY_COLORS}
            />
          </div>

          {/* Row 2: Environment + Component Types */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '32px' }}>
            <HorizontalBarChart
                title="Environment Distribution"
                data={envData}
                colorMap={ENV_COLORS}
            />
            <DonutChart
                title="Component Types"
                data={compTypeData}
            />
          </div>

          {/* Row 3: Risk Trend + Remediation */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '32px' }}>
            <RiskTrendChart data={trendData} />
            <RemediationChart stats={remStats} />
          </div>

          {/* Row 4: CVE Severity + Top Apps */}
          {sevData.length > 0 && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '32px' }}>
              <DonutChart
                  title="CVE Severity Breakdown"
                  data={sevData}
                  colorMap={SEVERITY_COLORS}
              />
              <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>
                  CVE Summary
                </h2>
                <div style={{ padding: 20 }}>
                  {sevData.map((s) => (
                      <div
                          key={s.name}
                          style={{
                              display: 'flex',
                              justifyContent:
                                  'space-between',
                              padding: '8px 0',
                              borderBottom:
                                  '1px solid #E5E5E5',
                          }}
                      >
                        <span
                            style={{
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '12px',
                                fontWeight: 500,
                                textTransform: 'uppercase',
                                backgroundColor: s.name === 'critical' ? '#FDE8E8' : s.name === 'high' ? '#FFF4E5' : '#E6F4EA',
                                color: s.name === 'critical' ? '#D13438' : s.name === 'high' ? '#F4B400' : '#107C10'
                            }}
                        >
                          {s.name}
                        </span>
                        <strong>{s.value}</strong>
                      </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Row 5: Recent Applications */}
          <div style={{ marginBottom: '32px' }}>
            <RecentAppsTable apps={apps} />
          </div>
        </div>
    );
}
