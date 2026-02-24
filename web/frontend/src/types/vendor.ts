// Vendor type definitions for SD-WAN Triage Tool runbook system

export type VendorID =
  | 'cisco'
  | 'velocloud'
  | 'silverpeak'
  | 'fortinet'
  | 'juniper'
  | 'paloalto'
  | 'citrix'
  | 'versa';

export type PrimaryInterface = 'cli' | 'gui' | 'hybrid';

export interface RunbookStep {
  command?: string;
  description: string;
  gui?: string;
  script?: string;
  api?: string;
}

export interface VendorFindingRunbook {
  diagnose: {
    gui?: string[];
    cli?: string[];
    script?: string[];
  };
  fix: {
    gui?: string[];
    cli?: string[];
    script?: string[];
  };
  verify: {
    gui?: string[];
    cli?: string[];
    script?: string[];
  };
  warnings: string[];
  knownBugs?: string[];
  recommendedVersions?: string[];
  documentationLinks?: { title: string; url: string }[];
  tacNotes?: string[];
}

export interface VendorGettingStarted {
  primer: string;
  interfaceNote: string;
  loginInfo: string;
  commonMistakes: string[];
  quickLinks: { title: string; url: string }[];
}

export interface VendorRunbook {
  vendor: string;
  vendorKey: VendorID;
  logo: string;
  color: string;
  bgColor: string;
  borderColor: string;
  primaryInterface: PrimaryInterface;
  defaultUrl?: string;
  authentication: string;
  gettingStarted: VendorGettingStarted;
  findings: Record<string, VendorFindingRunbook>;
}

export type VendorRunbookRegistry = Record<string, VendorRunbook>;

// Finding keys that every vendor runbook must cover
export const REQUIRED_FINDING_KEYS = [
  'tunnel_flapping',
  'packet_loss',
  'tcp_retransmission',
  'ddos_syn_flood',
  'c2_beaconing',
  'dns_tunneling',
  'port_scan',
  'tcp_handshake_failure',
  'arp_conflict',
  'voip_quality',
  'dhcp_rogue_server',
  'ntp_amplification',
  'tcp_zero_window',
  'tcp_out_of_order',
  'tls_weakness',
  'hsrp_instability',
] as const;

export type RequiredFindingKey = typeof REQUIRED_FINDING_KEYS[number];
