import React, { useState } from 'react';
import Header from './Header';
import Sidebar from './Sidebar';

function AppShell({ children }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#F7F8FA' }}>
      <Header />
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
      <main style={{
        marginLeft: sidebarCollapsed ? '72px' : '240px',
        marginTop: '60px',
        minHeight: 'calc(100vh - 60px)',
        padding: '32px',
        transition: 'margin-left 200ms ease-in-out'
      }}>
        {children}
      </main>
    </div>
  );
}

export default AppShell;
