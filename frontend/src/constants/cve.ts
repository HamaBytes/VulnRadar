export const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

export const PROJECT_STATUSES = [
    'analysis',
    'mitigation_planned',
    'remediating',
    'risk_accepted',
] as const;
