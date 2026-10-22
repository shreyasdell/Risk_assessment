import React from 'react';
import { NavLink } from 'react-router-dom';

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <h1>TPRA Tool</h1>
        <span>Third Party Risk Assessment</span>
      </div>
      <ul className="sidebar-nav">
        <li>
          <NavLink to="/dashboard" end>
            Dashboard
          </NavLink>
        </li>
        <li>
          <NavLink to="/vendors">
            Vendors
          </NavLink>
        </li>
        <li>
          <NavLink to="/applications">
            Applications
          </NavLink>
        </li>
      </ul>
    </aside>
  );
}

export default Sidebar;
