import { describe, it, expect } from 'vitest';
import { vendorRunbooks, getVendorRunbook, getVendorFindingRunbook } from './vendorRunbooks';
import { issueKnowledgeBase } from './knowledgeBase';
import { REQUIRED_FINDING_KEYS } from '../types/vendor';

const ALL_VENDOR_KEYS = Object.keys(vendorRunbooks);

const REQUIRED_FINDINGS = [
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
];

describe('Vendor Runbook Coverage', () => {
  it('should have 8 vendor runbooks', () => {
    expect(ALL_VENDOR_KEYS.length).toBe(8);
  });

  ALL_VENDOR_KEYS.forEach(vendorKey => {
    describe(`${vendorKey}`, () => {
      const vendor = vendorRunbooks[vendorKey];

      it('should have required metadata', () => {
        expect(vendor.vendor).toBeTruthy();
        expect(vendor.vendorKey).toBeTruthy();
        expect(vendor.logo).toBeTruthy();
        expect(vendor.primaryInterface).toMatch(/^(cli|gui|hybrid)$/);
        expect(vendor.authentication).toBeTruthy();
        expect(vendor.gettingStarted).toBeTruthy();
        expect(vendor.gettingStarted.primer).toBeTruthy();
        expect(vendor.gettingStarted.interfaceNote).toBeTruthy();
        expect(vendor.gettingStarted.loginInfo).toBeTruthy();
        expect(vendor.gettingStarted.commonMistakes.length).toBeGreaterThan(0);
        expect(vendor.gettingStarted.quickLinks.length).toBeGreaterThan(0);
      });

      REQUIRED_FINDINGS.forEach(findingKey => {
        it(`should have runbook for ${findingKey}`, () => {
          const finding = vendor.findings[findingKey];
          expect(finding).toBeDefined();
          expect(finding.warnings.length).toBeGreaterThan(0);

          // Diagnose must have at least one method (gui, cli, or script)
          const diagMethods = [finding.diagnose.gui, finding.diagnose.cli, finding.diagnose.script].filter(m => m && m.length > 0);
          expect(diagMethods.length).toBeGreaterThan(0);

          // Fix must have at least one method
          const fixMethods = [finding.fix.gui, finding.fix.cli, finding.fix.script].filter(m => m && m.length > 0);
          expect(fixMethods.length).toBeGreaterThan(0);

          // Verify must have at least one method
          const verifyMethods = [finding.verify.gui, finding.verify.cli, finding.verify.script].filter(m => m && m.length > 0);
          expect(verifyMethods.length).toBeGreaterThan(0);
        });
      });
    });
  });
});

describe('getVendorRunbook', () => {
  const testCases: [string, string][] = [
    ['Cisco SD-WAN (Viptela)', 'Cisco SD-WAN'],
    ['VMware SD-WAN (VeloCloud)', 'VMware SD-WAN'],
    ['Aruba EdgeConnect (Silver Peak)', 'Silver Peak'],
    ['Fortinet SD-WAN', 'Fortinet'],
    ['Juniper SD-WAN (Session Smart / Mist)', 'Juniper'],
    ['Palo Alto Prisma SD-WAN (CloudGenix)', 'Palo Alto'],
    ['Citrix SD-WAN', 'Citrix SD-WAN'],
    ['Versa Networks SD-WAN', 'Versa Networks'],
  ];

  testCases.forEach(([input, expectedKey]) => {
    it(`should match "${input}" to "${expectedKey}"`, () => {
      const result = getVendorRunbook(input);
      expect(result).toBeDefined();
      expect(result!.vendor).toBe(vendorRunbooks[expectedKey].vendor);
    });
  });

  // Fallback name matching
  const fallbackCases: [string, string][] = [
    ['viptela', 'Cisco SD-WAN'],
    ['vmanage', 'Cisco SD-WAN'],
    ['velocloud', 'VMware SD-WAN'],
    ['vmware', 'VMware SD-WAN'],
    ['silver peak', 'Silver Peak'],
    ['aruba', 'Silver Peak'],
    ['edgeconnect', 'Silver Peak'],
    ['fortigate', 'Fortinet'],
    ['fortios', 'Fortinet'],
    ['128t', 'Juniper'],
    ['ssr', 'Juniper'],
    ['mist', 'Juniper'],
    ['prisma', 'Palo Alto'],
    ['cloudgenix', 'Palo Alto'],
    ['citrix', 'Citrix SD-WAN'],
    ['netscaler', 'Citrix SD-WAN'],
    ['versa', 'Versa Networks'],
    ['flexvnf', 'Versa Networks'],
  ];

  fallbackCases.forEach(([input, expectedKey]) => {
    it(`should match fallback "${input}" to "${expectedKey}"`, () => {
      const result = getVendorRunbook(input);
      expect(result).toBeDefined();
      expect(result!.vendor).toBe(vendorRunbooks[expectedKey].vendor);
    });
  });

  it('should return null for unknown vendor', () => {
    expect(getVendorRunbook('Unknown Vendor XYZ')).toBeNull();
  });
});

describe('getVendorFindingRunbook', () => {
  it('should return finding runbook for valid vendor and finding', () => {
    const result = getVendorFindingRunbook('VMware SD-WAN (VeloCloud)', 'tunnel_flapping');
    expect(result).toBeDefined();
    expect(result!.diagnose.gui).toBeDefined();
    expect(result!.diagnose.gui!.length).toBeGreaterThan(0);
  });

  it('should return null for valid vendor but invalid finding', () => {
    const result = getVendorFindingRunbook('Cisco SD-WAN', 'nonexistent_finding');
    expect(result).toBeNull();
  });

  it('should return null for invalid vendor', () => {
    const result = getVendorFindingRunbook('Unknown Vendor', 'tunnel_flapping');
    expect(result).toBeNull();
  });
});

describe('REQUIRED_FINDING_KEYS type matches test list', () => {
  it('should have same 16 keys in REQUIRED_FINDING_KEYS type and REQUIRED_FINDINGS array', () => {
    const typeKeys = [...REQUIRED_FINDING_KEYS].sort();
    const testKeys = [...REQUIRED_FINDINGS].sort();
    expect(typeKeys).toEqual(testKeys);
  });
});

describe('Knowledge Base Neutrality', () => {
  // Cisco-specific CLI patterns that should NOT appear in the generic knowledge base
  const ciscoKbPatterns = [
    'show sdwan',
    'show standby brief',
    'show vrrp brief',
    'show ip cef',
    'show platform hardware',
    'show ip dhcp snooping',
    'show mac address-table',
    'show policy-map interface',
    'ip access-list extended',
    'ip access-group',
    'vmanage >',
    'cisco tac',
    'ios-xe',
    'vedge',
    'cedge',
    'vsmart',
    'vbond',
  ];

  it('should not contain Cisco-specific CLI in knowledge base tacTip fields', () => {
    const violations: string[] = [];
    Object.entries(issueKnowledgeBase).forEach(([key, entry]) => {
      if (entry.tacTip) {
        ciscoKbPatterns.forEach(pattern => {
          if (entry.tacTip!.toLowerCase().includes(pattern.toLowerCase())) {
            violations.push(`${key}.tacTip: "${entry.tacTip}" contains "${pattern}"`);
          }
        });
      }
    });
    expect(violations).toEqual([]);
  });

  it('should not contain Cisco-specific CLI in knowledge base commands arrays', () => {
    const violations: string[] = [];
    Object.entries(issueKnowledgeBase).forEach(([key, entry]) => {
      if (entry.commands) {
        entry.commands.forEach(cmd => {
          ciscoKbPatterns.forEach(pattern => {
            if (cmd.toLowerCase().includes(pattern.toLowerCase())) {
              violations.push(`${key}.commands: "${cmd}" contains "${pattern}"`);
            }
          });
        });
      }
    });
    expect(violations).toEqual([]);
  });

  it('should not contain Cisco-specific CLI in knowledge base how arrays', () => {
    // Patterns that are clearly Cisco-specific IOS syntax (not generic descriptions)
    const ciscoHowPatterns = [
      'ip access-list extended',
      'ip access-group',
      'show standby brief',
      'show vrrp brief',
      'show ip cef',
      'show platform hardware',
      'show ip dhcp snooping',
      'show mac address-table',
      'vmanage >',
      'cisco tac',
    ];
    const violations: string[] = [];
    Object.entries(issueKnowledgeBase).forEach(([key, entry]) => {
      entry.how.forEach(step => {
        ciscoHowPatterns.forEach(pattern => {
          if (step.toLowerCase().includes(pattern.toLowerCase())) {
            violations.push(`${key}.how: "${step}" contains "${pattern}"`);
          }
        });
      });
    });
    expect(violations).toEqual([]);
  });

  it('should not reference "Cisco TAC" in any knowledge base field', () => {
    const violations: string[] = [];
    Object.entries(issueKnowledgeBase).forEach(([key, entry]) => {
      const allText = [
        entry.what,
        entry.why,
        entry.eli5,
        entry.tacTip || '',
        ...entry.how,
        ...(entry.commands || []),
      ];
      allText.forEach(text => {
        if (text.toLowerCase().includes('cisco tac')) {
          violations.push(`${key}: "${text}" contains "Cisco TAC"`);
        }
      });
    });
    expect(violations).toEqual([]);
  });

  it('should have all required finding keys covered by knowledge base or vendor runbooks', () => {
    // Every required finding key should either have a KB entry or be covered by all vendor runbooks
    REQUIRED_FINDING_KEYS.forEach(findingKey => {
      const hasKbEntry = issueKnowledgeBase[findingKey] !== undefined;
      const allVendorsCovered = ALL_VENDOR_KEYS.every(
        vendorKey => vendorRunbooks[vendorKey].findings[findingKey] !== undefined
      );
      expect(hasKbEntry || allVendorsCovered).toBe(true);
    });
  });
});

describe('No Cisco CLI in non-Cisco vendor runbooks', () => {
  // Use Cisco-specific subcommands to avoid false positives with Versa OS which also uses "show sdwan"
  const ciscoPatterns = [
    'show sdwan omp',
    'show sdwan bfd',
    'show sdwan control',
    'show sdwan zbfw',
    'show sdwan dpi',
    'show sdwan ipsec',
    'show sdwan policy from-vsmart',
    'show sdwan appqoe',
    'show sdwan running-config',
    'show standby',
    'show ip cef',
    'show platform hardware',
    'vManage >',
    'ip access-list extended',
    'ip access-group',
    'parameter-map type umbrella',
  ];

  const nonCiscoVendors = ALL_VENDOR_KEYS.filter(k => k !== 'Cisco SD-WAN');

  nonCiscoVendors.forEach(vendorKey => {
    describe(`${vendorKey}`, () => {
      it('should not contain Cisco CLI commands in any finding', () => {
        const vendor = vendorRunbooks[vendorKey];
        const violations: string[] = [];

        Object.entries(vendor.findings).forEach(([findingKey, finding]) => {
          const allStrings: string[] = [
            ...(finding.diagnose.cli || []),
            ...(finding.diagnose.gui || []),
            ...(finding.diagnose.script || []),
            ...(finding.fix.cli || []),
            ...(finding.fix.gui || []),
            ...(finding.fix.script || []),
            ...(finding.verify.cli || []),
            ...(finding.verify.gui || []),
            ...(finding.verify.script || []),
            ...finding.warnings,
            ...(finding.tacNotes || []),
          ];

          allStrings.forEach(str => {
            ciscoPatterns.forEach(pattern => {
              if (str.toLowerCase().includes(pattern.toLowerCase())) {
                violations.push(`${findingKey}: "${str}" contains Cisco pattern "${pattern}"`);
              }
            });
          });
        });

        expect(violations).toEqual([]);
      });
    });
  });
});
