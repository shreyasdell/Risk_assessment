import React, { useState } from 'react';
import Header from './Header';
import Sidebar from './Sidebar';

function AppShell({ children }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#F5F7FA' }}>
      <Header />
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
      <main style={{
        marginLeft: sidebarCollapsed ? '64px' : '256px',
        marginTop: '56px',
        minHeight: 'calc(100vh - 56px)',
        padding: '24px',
        transition: 'margin-left 150ms ease-in-out'
      }}>
        {children}
      </main>
    </div>
  );
}

export default AppShell;
