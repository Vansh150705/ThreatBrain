import type { TriageEventPayload } from "./api/types";

// Pre-built demo scenarios that show off different agents
export interface Scenario {
  id: string;
  emoji: string;
  title: string;
  blurb: string;
  event: TriageEventPayload;
}

export const SCENARIOS: Scenario[] = [
  {
    id: "ssh-brute-force",
    emoji: "🔓",
    title: "SSH brute-force from suspicious IP",
    blurb: "Triggers IP enrichment via AbuseIPDB. Hits Triage + Threat Intel + Investigation.",
    event: {
      title: "Multiple failed SSH login attempts from foreign IP",
      description:
        "Approximately 1,200 failed SSH login attempts in the last hour targeting root and admin accounts on prod-web-01 from a Russian IP address known for botnet activity.",
      source: "auth_log",
      event_type: "authentication_failure",
      source_ip: "203.0.113.42",
      destination_ip: "10.0.1.10",
      destination_port: 22,
      username: "root",
      asset_name: "prod-web-01",
      asset_type: "server",
      asset_environment: "production",
      asset_criticality: "high",
    },
  },
  {
    id: "oauth-grant",
    emoji: "🔑",
    title: "Suspicious OAuth grant to unknown app",
    blurb: "Identity-layer threat. Tests compliance reasoning (GDPR + access governance).",
    event: {
      title: "OAuth token granted to unverified third-party app",
      description:
        "A user granted OAuth scopes 'mail.read' and 'files.read.all' to a third-party app that has never appeared in our tenant before. The app's publisher is unverified.",
      source: "okta",
      event_type: "oauth_grant",
      username: "marcus.chen@acme.example",
      asset_name: "okta-tenant-acme",
      asset_type: "saas",
      asset_environment: "production",
      asset_criticality: "high",
    },
  },
  {
    id: "s3-public",
    emoji: "🪣",
    title: "S3 bucket made public",
    blurb: "Cloud misconfiguration. Strong Compliance + Response signal.",
    event: {
      title: "Production S3 bucket ACL changed to public-read",
      description:
        "Bucket 'acme-customer-uploads' had its ACL changed from private to public-read by service account 'svc-ci-deployer'. The bucket contains user-uploaded files including PII.",
      source: "cloudtrail",
      event_type: "s3_acl_change",
      username: "svc-ci-deployer",
      asset_name: "acme-customer-uploads",
      asset_type: "s3_bucket",
      asset_environment: "production",
      asset_criticality: "critical",
    },
  },
  {
    id: "impossible-travel",
    emoji: "🌍",
    title: "Impossible-travel login",
    blurb: "Behavioral anomaly. Investigation agent shines here.",
    event: {
      title: "Impossible-travel login to corporate Okta",
      description:
        "User marcus.chen@acme.example logged in from Moscow (RU) at 03:25 UTC and from San Francisco (US) at 03:33 UTC. The geographic distance is impossible in 8 minutes.",
      source: "okta",
      event_type: "anomalous_login",
      source_ip: "203.0.113.42",
      username: "marcus.chen@acme.example",
      asset_name: "okta-tenant-acme",
      asset_type: "saas",
      asset_environment: "production",
      asset_criticality: "high",
    },
  },
];