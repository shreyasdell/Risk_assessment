import React from 'react';
import { Outlet } from 'react-router-dom';
import AppShell from '../AppShell/AppShell';
import Breadcrumb from '../AppShell/Breadcrumb';

function Layout() {
  return (
    <AppShell>
      <Breadcrumb />
      <Outlet />
    </AppShell>
  );
}

export default Layout;
