import React from 'react';
import { Link, useLocation } from 'react-router-dom';

function Breadcrumb() {
  const location = useLocation();
  
  const pathnames = location.pathname.split('/').filter(x => x);
  
  const breadcrumbMap = {
    'dashboard': 'Dashboard',
    'vendors': 'Vendors',
    'applications': 'Applications',
    'components': 'Components',
    'cves': 'CVEs',
    'reports': 'Reports',
    'remediations': 'Remediations',
    'nist': 'NIST Recommendations',
    'audit': 'Audit Logs',
    'settings': 'Settings',
    'assessments': 'Assessments',
    'risk-register': 'Risk Register'
  };

  return (
    <nav style={{ marginBottom: '16px' }}>
      <ol style={{
        display: 'flex',
        listStyle: 'none',
        margin: 0,
        padding: 0,
        fontSize: '13px',
        color: '#606060'
      }}>
        <li style={{ display: 'flex', alignItems: 'center' }}>
          <Link to="/" style={{ color: '#0076CE', textDecoration: 'none' }}>
            Dashboard
          </Link>
        </li>
        {pathnames.map((name, index) => {
          const routeTo = `/${pathnames.slice(0, index + 1).join('/')}`;
          const isLast = index === pathnames.length - 1;
          const displayName = breadcrumbMap[name] || name;
          
          return (
            <li key={name} style={{ display: 'flex', alignItems: 'center' }}>
              <span style={{ margin: '0 8px', color: '#D9D9D9' }}>/</span>
              {isLast ? (
                <span style={{ color: '#202020', fontWeight: 500 }}>{displayName}</span>
              ) : (
                <Link to={routeTo} style={{ color: '#0076CE', textDecoration: 'none' }}>
                  {displayName}
                </Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export default Breadcrumb;
