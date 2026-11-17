"""
PDF Report Configuration

Centralized configuration for report generation.
"""

from reportlab.lib import colors

# Color scheme matching requirements
COLORS = {
    'critical': colors.HexColor('#D13438'),
    'high': colors.HexColor('#FF8C00'),
    'medium': colors.HexColor('#F4B400'),
    'low': colors.HexColor('#107C10'),
    'header_bg': colors.HexColor('#202020'),
    'header_text': colors.HexColor('#FFFFFF'),
    'border': colors.HexColor('#D9D9D9'),
    'text': colors.HexColor('#202020'),
    'light_gray': colors.HexColor('#F5F5F5'),
}

# Page settings
PAGE_SIZE = 'A4'
MARGINS = {
    'top': 0.75,
    'bottom': 0.75,
    'left': 0.75,
    'right': 0.75,
}

# Risk scoring weights
RISK_WEIGHTS = {
    'critical': 10,
    'high': 7,
    'medium': 4,
    'low': 1,
}

# Report types
REPORT_TYPES = {
    'full': 'Full Report',
    'executive': 'Executive Summary Only',
}
