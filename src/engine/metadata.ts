import type { DetectedEntity, EnabledEntityMap, EntityMeta, EntityType, RiskSummary } from './types';

export const ENTITY_ORDER: EntityType[] = [
  'EMAIL',
  'PHONE',
  'IP_ADDRESS',
  'PAN',
  'AADHAAR',
  'CREDIT_CARD',
  'CUSTOM',
];

export const ENTITY_META: Record<EntityType, EntityMeta> = {
  EMAIL: {
    id: 'EMAIL',
    label: 'Email Address',
    shortLabel: 'Email',
    prefix: 'USER',
    priority: 1,
    exampleMask: 'a***@domain.com',
    severityWeight: 8,
  },
  CREDIT_CARD: {
    id: 'CREDIT_CARD',
    label: 'Credit Card (Luhn)',
    shortLabel: 'Credit Card',
    prefix: 'CARD',
    priority: 2,
    exampleMask: 'XXXX-XXXX-XXXX-9014',
    severityWeight: 25,
  },
  IP_ADDRESS: {
    id: 'IP_ADDRESS',
    label: 'IP Address (v4/v6)',
    shortLabel: 'IP Address',
    prefix: 'IP',
    priority: 3,
    exampleMask: '192.168.XXX.XXX',
    severityWeight: 6,
  },
  PAN: {
    id: 'PAN',
    label: 'Indian PAN',
    shortLabel: 'Indian PAN',
    prefix: 'PAN',
    priority: 4,
    exampleMask: 'XXXXX2318J',
    severityWeight: 20,
  },
  AADHAAR: {
    id: 'AADHAAR',
    label: 'Indian Aadhaar',
    shortLabel: 'Aadhaar',
    prefix: 'AADHAAR',
    priority: 5,
    exampleMask: 'XXXX XXXX 3340',
    severityWeight: 25,
  },
  PHONE: {
    id: 'PHONE',
    label: 'Phone Number',
    shortLabel: 'Phone',
    prefix: 'PHONE',
    priority: 6,
    exampleMask: '+91-XXXXXX4510',
    severityWeight: 10,
  },
  CUSTOM: {
    id: 'CUSTOM',
    label: 'Custom Pattern',
    shortLabel: 'Custom',
    prefix: 'CUSTOM',
    priority: 7,
    exampleMask: 'XX***XX',
    severityWeight: 12,
  },
};

export const DEFAULT_ENABLED_TYPES: EnabledEntityMap = {
  EMAIL: true,
  PHONE: true,
  IP_ADDRESS: true,
  PAN: true,
  AADHAAR: true,
  CREDIT_CARD: true,
  CUSTOM: true,
};

/**
 * Computes an aggregate 0–100 privacy exposure risk score from detected entities.
 */
export function computeRiskSummary(matches: DetectedEntity[]): RiskSummary {
  if (matches.length === 0) return { score: 0, level: 'Clean' };
  const rawWeight = matches.reduce((sum, m) => sum + ENTITY_META[m.type].severityWeight, 0);
  const score = Math.min(100, rawWeight);
  let level: RiskSummary['level'] = 'Low';
  if (score >= 80) level = 'Critical';
  else if (score >= 55) level = 'High';
  else if (score >= 25) level = 'Moderate';
  return { score, level };
}
