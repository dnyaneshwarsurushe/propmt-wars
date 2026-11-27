export interface SampleDataset {
  id: 'support_ticket' | 'hr_resume' | 'billing_csv';
  label: string;
  filename: string;
  description: string;
  text: string;
}

export const SAMPLES: Record<SampleDataset['id'], SampleDataset> = {
  support_ticket: {
    id: 'support_ticket',
    label: 'Support Ticket & Logs (.txt)',
    filename: 'support_incident_log.txt',
    description: 'Security ticket with recurring emails, PAN/Aadhaar KYC, IPv4/IPv6, Luhn cards, and a 16-digit non-Luhn decoy.',
    text: `[2026-11-27 10:14:22] INCIDENT #INC-40921 — Priority: HIGH
Reporter: Ananya Deshmukh <ananya.deshmukh@finvault.in>
Backup Contact: +91 98201 44510 | US Desk: (415) 555-0199
Client IP: 192.168.42.18 (Gateway IPv6: 2001:0db8:85a3::8a2e:0370:7334)
Release Tag: v1.2.3.4 | Epoch: 1732700000

Customer KYC Verification Notes:
- PAN Card Submitted: BNZAA2318J
- Aadhaar Number: 4512 8891 3340 (Linked mobile: 9820144510)
- Primary Card Used (Visa): 4532-1234-5678-9014
- Corporate Backup Card (Mastercard): 5425 2334 3010 9903
- Internal Order Tracking Ref (16-digit non-Luhn): 4532-1234-5678-9010

Escalation Audit:
Follow-up email sent to ananya.deshmukh@finvault.in and sec-ops@finvault.in.
Agent session originated from 10.24.198.7; callback requested on +91-9820144510.
Confirmed PAN BNZAA2318J matches KYC record for Aadhaar 4512-8891-3340.`,
  },
  hr_resume: {
    id: 'hr_resume',
    label: 'HR Candidate Resume (.txt)',
    filename: 'candidate_resume.txt',
    description: 'Onboarding profile with tax identifiers, phone formats, and payroll reference IDs.',
    text: `CURRICULUM VITAE — RAHUL MEHTA
Email: rahul.mehta.dev@gmail.com | Alt: r.mehta@cloudscale.io
Phone: +91-9876543210 | Home: 022-26541234
Git Host IP: 172.16.254.1

Tax & Identity Details (Onboarding Packet):
PAN: ABCDE1234F
Aadhaar: 2345-6789-0123
Reimbursement Card: 4111111111111111
Payroll Batch ID (16-digit non-Luhn): 9988776655443322

Reference Check:
Manager Priya Nair (priya.nair@cloudscale.io, +1 (650) 555-0142) verified rahul.mehta.dev@gmail.com.`,
  },
  billing_csv: {
    id: 'billing_csv',
    label: 'Clinical & Billing Export (.csv)',
    filename: 'patient_billing_export.csv',
    description: 'Structured CSV export preserving delimiter integrity across recurring patients.',
    text: `patient_id,email,phone,pan,aadhaar,card_number,source_ip,txn_ref_16d
PT-101,meera.iyer@medcare.org,+91 98111 22334,CHJPM1928K,3456 7890 1234,4539 1488 0343 6467,203.0.113.45,1234567890123456
PT-102,arjun.verma@outlook.com,9988776655,DLKPA4421R,7890-1234-5678,3782 822463 10005,198.51.100.12,8888777766665555
PT-103,meera.iyer@medcare.org,+91-9811122334,CHJPM1928K,345678901234,6011000990139424,203.0.113.45,1111222233334445`,
  },
};

export const DEFAULT_SAMPLE_ID: SampleDataset['id'] = 'support_ticket';
