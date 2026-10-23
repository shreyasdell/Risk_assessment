import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';

const Icons = {
  Dashboard: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <rect x="2" y="2" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
      <rect x="11" y="2" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
      <rect x="2" y="11" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
      <rect x="11" y="11" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  ),
  Assessments: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M3 4H17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M3 8H17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M3 12H17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M3 16H17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  Risk: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M10 2L2 18H18L10 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M10 8V12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M10 15H10.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  Applications: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <rect x="3" y="3" width="14" height="14" rx="2" stroke="currentColor" strokeWidth="1.5" />
      <path d="M3 8H17" stroke="currentColor" strokeWidth="1.5" />
      <path d="M8 3V17" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  ),
  Components: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M10 2L18 6V14L10 18L2 14V6L10 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M10 2V10" stroke="currentColor" strokeWidth="1.5" />
      <path d="M10 10L18 6" stroke="currentColor" strokeWidth="1.5" />
      <path d="M10 10L2 6" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  ),
  CVEs: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M10 2C5.58172 2 2 5.58172 2 10C2 14.4183 5.58172 18 10 18C14.4183 18 18 14.4183 18 10C18 5.58172 14.4183 2 10 2Z" stroke="currentColor" strokeWidth="1.5" />
      <path d="M10 6V10L13 13" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  Reports: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M4 4H16" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4 8H16" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4 12H10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4 16H6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  Remediations: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M10 2L2 7V17H18V7L10 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M10 10V17" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  ),
  NIST: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M4 4H16" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4 8H16" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4 12H12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4 16H8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  Audit: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M9 5H11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M9 9H11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M9 13H11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M3 3H17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M3 17H17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M3 3V17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M17 3V17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  Settings: () => (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <circle cx="10" cy="10" r="3" stroke="currentColor" strokeWidth="1.5" />
      <path d="M10 2V4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M10 16V18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M2 10H4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M16 10H18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4.93 4.93L6.34 6.34" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M13.66 13.66L15.07 15.07" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M4.93 15.07L6.34 13.66" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M13.66 6.34L15.07 4.93" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  ChevronDown: () => (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
      <path d="M2 4L6 8L10 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  ChevronRight: () => (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
      <path d="M4 2L8 6L4 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  ChevronLeft: () => (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
      <path d="M8 2L4 6L8 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
};

function Sidebar({ collapsed, onToggle }) {
  const location = useLocation();
  const [expandedMenus, setExpandedMenus] = useState({});

  const menuItems = [
    { path: '/dashboard', icon: Icons.Dashboard, label: 'Dashboard' },
    { 
      icon: Icons.Assessments, 
      label: 'Assessments',
      children: [
        { path: '/assessments', label: 'All Assessments' },
        { path: '/assessments/new', label: 'New Assessment' }
      ]
    },
    { path: '/risk-register', icon: Icons.Risk, label: 'Risk Register' },
    { path: '/applications', icon: Icons.Applications, label: 'Applications' },
    { path: '/components', icon: Icons.Components, label: 'Components' },
    { path: '/cves', icon: Icons.CVEs, label: 'CVEs' },
    { path: '/reports', icon: Icons.Reports, label: 'Reports' },
    { path: '/remediations', icon: Icons.Remediations, label: 'Remediations' },
    { path: '/nist', icon: Icons.NIST, label: 'NIST Recommendations' },
    { path: '/audit', icon: Icons.Audit, label: 'Audit Logs' },
    { path: '/settings', icon: Icons.Settings, label: 'Settings' }
  ];

  const toggleMenu = (label) => {
    setExpandedMenus(prev => ({
      ...prev,
      [label]: !prev[label]
    }));
  };

  const isActive = (path) => {
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  return (
    <aside style={{
      width: collapsed ? '64px' : '256px',
      height: 'calc(100vh - 56px)',
      backgroundColor: '#FFFFFF',
      borderRight: '1px solid #E0E0E0',
      position: 'fixed',
      top: '56px',
      left: 0,
      overflowY: 'auto',
      transition: 'width 150ms ease-in-out',
      zIndex: 1020
    }}>
      <button
        onClick={onToggle}
        style={{
          width: '100%',
          padding: '16px',
          background: 'none',
          border: 'none',
          borderBottom: '1px solid #E5E5E5',
          cursor: 'pointer',
          display: 'flex',
          justifyContent: collapsed ? 'center' : 'flex-end',
          color: '#606060'
        }}
      >
        {collapsed ? <Icons.ChevronRight /> : <Icons.ChevronLeft />}
      </button>

      <nav style={{ padding: collapsed ? '8px' : '16px' }}>
        {menuItems.map((item) => {
          const IconComponent = item.icon;
          if (item.children) {
            const isExpanded = expandedMenus[item.label];
            return (
              <div key={item.label}>
                <button
                  onClick={() => toggleMenu(item.label)}
                  style={{
                    width: '100%',
                    padding: collapsed ? '12px' : '12px 16px',
                    marginBottom: '4px',
                    background: 'none',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: collapsed ? '0' : '12px',
                    color: '#606060',
                    fontSize: '14px',
                    transition: 'background-color 150ms',
                    justifyContent: collapsed ? 'center' : 'flex-start'
                  }}
                >
                  <IconComponent />
                  {!collapsed && (
                    <>
                      <span>{item.label}</span>
                      <span style={{ marginLeft: 'auto' }}>
                        {isExpanded ? <Icons.ChevronDown /> : <Icons.ChevronRight />}
                      </span>
                    </>
                  )}
                </button>
                {!collapsed && isExpanded && (
                  <div style={{ marginLeft: '24px', marginTop: '4px' }}>
                    {item.children.map((child) => (
                      <NavLink
                        key={child.path}
                        to={child.path}
                        style={{
                          display: 'block',
                          padding: '8px 16px',
                          marginBottom: '2px',
                          color: isActive(child.path) ? '#0076CE' : '#606060',
                          textDecoration: 'none',
                          borderRadius: '4px',
                          fontSize: '13px',
                          backgroundColor: isActive(child.path) ? '#E5F3FF' : 'transparent'
                        }}
                      >
                        {child.label}
                      </NavLink>
                    ))}
                  </div>
                )}
              </div>
            );
          }

          return (
            <NavLink
              key={item.path}
              to={item.path}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: collapsed ? '0' : '12px',
                padding: collapsed ? '12px' : '12px 16px',
                marginBottom: '4px',
                color: isActive(item.path) ? '#0076CE' : '#606060',
                textDecoration: 'none',
                borderRadius: '4px',
                fontSize: '14px',
                backgroundColor: isActive(item.path) ? '#E5F3FF' : 'transparent',
                transition: 'background-color 150ms',
                justifyContent: collapsed ? 'center' : 'flex-start'
              }}
            >
              <IconComponent />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
}

export default Sidebar;
