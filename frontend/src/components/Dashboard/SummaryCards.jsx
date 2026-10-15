import React from 'react';

function SummaryCards({ summary }) {
  if (!summary) return null;

  const cards = [
    {
      label: 'Total Applications',
      value: summary.total_applications,
      style: 'info',
      subtitle: 'Registered apps'
    },
    {
      label: 'Total Vendors',
      value: summary.total_vendors,
      style: 'info',
      subtitle: 'Third-party vendors'
    },
    {
      label: 'Total Components',
      value: summary.total_components,
      style: 'info',
      subtitle: 'Libraries & packages'
    },
    {
      label: 'Critical Apps',
      value: summary.critical_applications,
      style: summary.critical_applications > 0 ? 'critical' : 'success',
      subtitle: 'Need immediate attention'
    },
  ];

  return (
    <div className="summary-grid">
      {cards.map((card, index) => (
        <div key={index} className={`summary-card ${card.style}`}>
          <div className="label">{card.label}</div>
          <div className="value">{card.value}</div>
          <div className="subtitle">{card.subtitle}</div>
        </div>
      ))}
    </div>
  );
}

export default SummaryCards;
