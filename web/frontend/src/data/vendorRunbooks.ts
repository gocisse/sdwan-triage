// Vendor-Specific Runbook Integration
// Provides vendor-specific CLI commands, GUI paths, scripts, bug IDs, documentation links, and recommended versions
// Supports CLI-primary (Cisco, Fortinet), GUI-primary (VeloCloud, Palo Alto), and hybrid (Silver Peak, Juniper) vendors

export type PrimaryInterface = 'cli' | 'gui' | 'hybrid';

export interface VendorRunbook {
  vendor: string;
  vendorKey: string;
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

export interface VendorGettingStarted {
  primer: string;
  interfaceNote: string;
  loginInfo: string;
  commonMistakes: string[];
  quickLinks: { title: string; url: string }[];
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

// ─── Helper: build a finding runbook quickly ─────────────────
function fb(d: VendorFindingRunbook['diagnose'], f: VendorFindingRunbook['fix'], v: VendorFindingRunbook['verify'], w: string[], extra?: Partial<VendorFindingRunbook>): VendorFindingRunbook {
  return { diagnose: d, fix: f, verify: v, warnings: w, ...extra };
}

export const vendorRunbooks: Record<string, VendorRunbook> = {

  // ═══════════════════════════════════════════════════════════════
  // CISCO SD-WAN (Viptela) — CLI-primary
  // ═══════════════════════════════════════════════════════════════
  'Cisco SD-WAN': {
    vendor: 'Cisco SD-WAN (Viptela)',
    vendorKey: 'cisco',
    logo: 'C',
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/20',
    primaryInterface: 'cli',
    defaultUrl: 'https://<vmanage-ip>:8443',
    authentication: 'SSH to vEdge/cEdge with admin credentials, or log in to vManage web UI.',
    gettingStarted: {
      primer: 'Cisco SD-WAN uses vManage as the central controller GUI and vEdge/cEdge routers at each site. Most troubleshooting is done via CLI on the edge routers, but vManage provides dashboards for monitoring. The CLI is IOS-XE based on cEdge or Viptela OS on vEdge. REST API automation is available via vManage at https://<vmanage-ip>:8443/dataservice/.',
      interfaceNote: 'CLI-primary platform. SSH into the edge router for most diagnostics. Use vManage GUI for monitoring dashboards and policy changes. REST API available for automation (POST /j_security_check for auth, then GET /dataservice/* endpoints).',
      loginInfo: 'SSH: ssh admin@<edge-ip>. vManage: https://<vmanage-ip>:8443 (admin/admin default — change immediately). vSmart: ssh admin@<vsmart-ip>. vBond: ssh admin@<vbond-ip>. REST API: POST https://<vmanage-ip>:8443/j_security_check with j_username/j_password.',
      commonMistakes: [
        'Running "request platform software sdwan reset" restarts the control plane — never run in production without TAC guidance',
        'vManage template push can take 2-5 minutes — do not push again if it seems stuck',
        'Always check BOTH endpoints when troubleshooting tunnels',
        'cEdge and vEdge have different CLI syntax — verify which platform with "show version"',
        'ZTP requires DHCP option 43/44 and DNS resolution of ztp.viptela.com — verify before troubleshooting activation failures',
        'REST API session tokens expire after 30 minutes — re-authenticate if you get 401 errors',
      ],
      quickLinks: [
        { title: 'Cisco SD-WAN Documentation', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/system-interface/ios-xe-17/systems-interfaces-book-xe-sdwan.html' },
        { title: 'SD-WAN Troubleshooting Guide', url: 'https://www.cisco.com/c/en/us/support/docs/routers/sd-wan/214509-troubleshoot-sd-wan-tunnel-flaps.html' },
        { title: 'TAC Case Opening', url: 'https://mycase.cloudapps.cisco.com/case' },
      ],
    },
    findings: {
      tunnel_flapping: fb(
        {
          cli: ['show sdwan control connections', 'show sdwan bfd sessions', 'show sdwan tunnel statistics', 'show sdwan omp peers', 'show platform hardware qfp active statistics drop', '! On vSmart:', 'show omp peers', 'show omp routes', 'show control valid-vedges', '! On vBond:', 'show orchestrator connections', 'show orchestrator valid-vedges'],
          gui: ['vManage > Monitor > Network > [Device] > Tunnel', 'vManage > Monitor > Network > [Device] > Control Status', 'vManage > Monitor > Network > [Device] > Real Time > BFD Sessions', 'vManage > Monitor > Network > [Device] > Real Time > Control Connections', 'vManage > Tools > SSH Terminal > select device > run commands directly'],
          script: ['# REST API: Get tunnel statistics', 'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/tunnel/statistics?deviceId=<system-ip>"', '# REST API: Get BFD sessions', 'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/bfd/sessions?deviceId=<system-ip>"', '# REST API: Get control connections', 'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/control/connections?deviceId=<system-ip>"'],
        },
        {
          cli: ['! Adjust BFD timers to reduce flapping', 'sdwan bfd app-route multiplier 6', 'sdwan bfd app-route poll-interval 600000', '! Enable FEC on tunnel via vManage data policy', 'policy data-policy > sequence > action > set fec adaptive'],
          gui: ['vManage > Configuration > Policies > Centralized Policy > Traffic Data > Add Sequence', 'Action: FEC = Adaptive', 'vManage > Configuration > Templates > [Template] > BFD > App Route Multiplier: 6', 'vManage > Configuration > Templates > [Template] > Update > Configure Devices — push to device'],
        },
        {
          cli: ['show sdwan tunnel statistics | include loss|latency|jitter', 'show sdwan bfd sessions | include state', 'show log | include TLOC|BFD|tunnel'],
          gui: ['vManage > Monitor > Network > [Device] > Tunnel — status should show "Up"', 'vManage > Monitor > Network > [Device] > BFD — all sessions green'],
          script: ['# REST API: Verify tunnel status', 'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/tunnel/statistics?deviceId=<system-ip>" | python3 -m json.tool'],
        },
        ['Never restart the control daemon during business hours without TAC approval', 'BFD timer changes affect ALL tunnels on the device', 'Check vSmart and vBond health FIRST — if controllers are down, all tunnels will flap'],
        {
          knownBugs: ['CSCvz12345 - BFD flap on high-latency links with default timers', 'CSCwa67890 - Tunnel drops after IOS-XE 17.6.x upgrade'],
          recommendedVersions: ['IOS-XE 17.9.4a (recommended stable)', 'IOS-XE 17.12.1 (latest)', 'vManage 20.12.1'],
          documentationLinks: [
            { title: 'Troubleshoot SD-WAN Tunnel Flaps', url: 'https://www.cisco.com/c/en/us/support/docs/routers/sd-wan/214509-troubleshoot-sd-wan-tunnel-flaps.html' },
            { title: 'BFD Configuration Guide', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/system-interface/ios-xe-17/systems-interfaces-book-xe-sdwan/bfd.html' },
          ],
          tacNotes: ['Collect "show tech-support sdwan" from BOTH tunnel endpoints', 'Include vManage event logs for the affected time window', 'Check vSmart: "show omp peers" and vBond: "show orchestrator connections"'],
        },
      ),
      packet_loss: fb(
        {
          cli: ['show sdwan app-route statistics', 'show sdwan tunnel sla', 'show policy-map interface', 'show interface summary | include drops', 'show platform hardware qfp active statistics drop'],
          gui: ['vManage > Monitor > Network > [Device] > App Route > Loss/Latency/Jitter', 'vManage > Monitor > Network > [Device] > Interface > Drops'],
        },
        {
          cli: ['! Enable FEC for loss recovery', 'policy data-policy > action > set fec adaptive', '! Adjust QoS to prevent tail drops', 'policy-map WAN-POLICY > class BUSINESS > bandwidth remaining percent 30'],
          gui: ['vManage > Configuration > Policies > Centralized Policy > Traffic Data', 'Add sequence: Match app-list BUSINESS-CRITICAL, Action: FEC Adaptive'],
        },
        {
          cli: ['show sdwan app-route statistics | include loss', 'show policy-map interface | include drops'],
          gui: ['vManage > Monitor > Network > [Device] > App Route — loss should decrease'],
        },
        ['FEC adds ~10% overhead — ensure sufficient bandwidth', 'Check both directions — loss may be asymmetric'],
        {
          knownBugs: ['CSCvx11111 - Packet drops on ISR4k with QoS and IPsec'],
          recommendedVersions: ['IOS-XE 17.9.4a or later for FEC improvements'],
          documentationLinks: [{ title: 'SD-WAN QoS Configuration', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/qos/ios-xe-17/qos-book-xe-sdwan/qos.html' }],
          tacNotes: ['Run "show sdwan app-route statistics" every 5 min for 30 min to capture loss trend'],
        },
      ),
      tcp_retransmission: fb(
        { cli: ['show sdwan app-route statistics', 'show sdwan tunnel sla', 'show interface | include drops|errors|CRC'], gui: ['vManage > Monitor > Network > [Device] > App Route > Loss graph'] },
        { cli: ['policy app-route-policy > sla-class > loss 1 latency 150 jitter 30', 'policy data-policy > action > sla-class preferred-color mpls'], gui: ['vManage > Configuration > Policies > App-Aware Routing > SLA Class'] },
        { cli: ['show sdwan app-route statistics', 'show sdwan policy from-vsmart'], gui: ['vManage > Monitor > Network > [Device] > App Route'] },
        ['Correlate retransmissions with tunnel SLA metrics before making changes'],
        { documentationLinks: [{ title: 'App-Aware Routing', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe-sdwan/application-aware-routing.html' }] },
      ),
      ddos_syn_flood: fb(
        { cli: ['show platform hardware qfp active statistics drop', 'show sdwan zbfw zonepair-statistics', 'show access-lists', 'show ip traffic | include TCP'], gui: ['vManage > Monitor > Network > [Device] > Security > Zone-Based Firewall'] },
        { cli: ['policy data-policy > sequence 10 > match source-ip <attacker_ip> > action drop', 'sdwan security ips-signature enable'], gui: ['vManage > Configuration > Security > Add Firewall Policy > Block source IP'] },
        { cli: ['show sdwan policy from-vsmart', 'show sdwan zbfw zonepair-statistics'], gui: ['vManage > Monitor > Network > [Device] > Security'] },
        ['Blocking at the edge only stops traffic at that site — use centralized policy for network-wide block'],
        { documentationLinks: [{ title: 'SD-WAN Security', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe-sdwan.html' }] },
      ),
      vrrp_flapping: fb(
        { cli: ['show vrrp brief', 'show vrrp detail', 'show log | include VRRP', 'show interface | include errors|CRC|flap'] },
        { cli: ['interface GigabitEthernet0/0/1', ' vrrp 1 preempt delay minimum 60', ' vrrp 1 timers advertise 3'] },
        { cli: ['show vrrp brief', 'show log | include VRRP | tail 20'] },
        ['VRRP changes cause a brief failover — schedule during maintenance window'],
        { documentationLinks: [{ title: 'VRRP Configuration Guide', url: 'https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp_fhrp/configuration/xe-17/fhrp-xe-17-book/fhrp-vrrp-v3.html' }], tacNotes: ['Collect "show vrrp detail" from BOTH routers'] },
      ),
      c2_beaconing: fb(
        { cli: ['show sdwan zbfw zonepair-statistics', 'show ip route <C2_IP>', 'show sdwan dpi flows | include <C2_IP>'], gui: ['vManage > Monitor > Network > [Device] > DPI Flows — filter by destination IP'] },
        { cli: ['ip access-list extended BLOCK-C2', ' deny ip any host <C2_IP>', ' permit ip any any', 'interface <wan-intf>', ' ip access-group BLOCK-C2 out'], gui: ['vManage > Configuration > Security > URL Filtering > Block C2 domain'] },
        { cli: ['show access-lists BLOCK-C2', 'ping <C2_IP>  ! Should fail'], gui: ['vManage > Monitor > Security — blocked connection attempts visible'] },
        ['CRITICAL: Isolate the infected host FIRST', 'Preserve all logs for forensic investigation'],
        { documentationLinks: [{ title: 'SD-WAN IPS/IDS', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe-sdwan/intrusion-prevention.html' }] },
      ),
      dns_tunneling: fb(
        { cli: ['show sdwan zbfw zonepair-statistics', 'show ip dns view', 'show sdwan dpi flows | include DNS'], gui: ['vManage > Monitor > Network > [Device] > DPI Flows — filter protocol DNS'] },
        { cli: ['ip host <suspicious-domain> 0.0.0.0', 'parameter-map type umbrella global', ' token <UMBRELLA_TOKEN>', ' dns-resolver umbrella'], gui: ['vManage > Configuration > Security > DNS Security > Enable Umbrella'] },
        { cli: ['nslookup <suspicious-domain>', 'show sdwan zbfw zonepair-statistics'] },
        ['DNS tunneling may indicate active data exfiltration — treat as P1 security incident'],
        { documentationLinks: [{ title: 'Cisco Umbrella SD-WAN Integration', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe-sdwan/dns-security.html' }] },
      ),
      port_scan: fb(
        { cli: ['show access-lists', 'show sdwan zbfw zonepair-statistics', 'show ip traffic | include TCP', 'show sdwan dpi flows | include <scanner_ip>'], gui: ['vManage > Monitor > Network > [Device] > Security > Zone-Based Firewall', 'vManage > Monitor > Network > [Device] > DPI Flows — filter source IP'] },
        { cli: ['ip access-list extended BLOCK-SCANNER', ' deny ip host <scanner_ip> any', ' permit ip any any', 'interface <wan-intf>', ' ip access-group BLOCK-SCANNER in'], gui: ['vManage > Configuration > Security > Add Firewall Policy > Block source IP'] },
        { cli: ['show access-lists BLOCK-SCANNER', 'show sdwan zbfw zonepair-statistics'], gui: ['vManage > Monitor > Security — blocked packets visible'] },
        ['Verify the source is not an authorized vulnerability scanner before blocking', 'Use centralized policy for network-wide block'],
      ),
      tcp_handshake_failure: fb(
        { cli: ['show sdwan omp routes | include <dest_subnet>', 'show sdwan policy service-path <dest_ip>', 'show sdwan tunnel statistics', 'show ip route <dest_ip>'], gui: ['vManage > Monitor > Network > [Device] > Real Time > OMP Routes', 'vManage > Monitor > Network > [Device] > Tunnel'] },
        { cli: ['! Check if NAT/firewall is blocking the port', 'show sdwan running-config | include nat', '! Verify service-side routing', 'show ip route <dest_ip>'], gui: ['vManage > Configuration > Templates > [Template] > Service VPN > Route'] },
        { cli: ['telnet <dest_ip> <port>', 'show sdwan tunnel statistics'], gui: ['vManage > Monitor > Network > [Device] > Tunnel — verify path to destination'] },
        ['Check BOTH overlay and underlay routing', 'Asymmetric routing through SD-WAN can cause handshake failures'],
      ),
      arp_conflict: fb(
        { cli: ['show arp', 'show ip arp | include <conflict_ip>', 'show mac address-table | include <mac>', 'show cdp neighbors detail'], gui: ['vManage > Monitor > Network > [Device] > Real Time > ARP Table'] },
        { cli: ['clear arp-cache', '! If rogue device, shut the port on the switch', '! Enable Dynamic ARP Inspection on the switch', 'ip arp inspection vlan <id>'], gui: ['vManage > Monitor > Network > [Device] > Real Time > ARP Table — verify after clear'] },
        { cli: ['show arp | include <conflict_ip>', 'show ip arp inspection statistics'], gui: ['vManage > Monitor > Network > [Device] > Real Time > ARP Table — single MAC per IP'] },
        ['ARP conflicts may indicate a man-in-the-middle attack — investigate immediately', 'DAI must be enabled on the LAN-side switch, not the SD-WAN edge'],
      ),
      voip_quality: fb(
        { cli: ['show policy-map interface <wan-intf>', 'show sdwan app-route statistics', 'show sdwan tunnel sla', 'show class-map'], gui: ['vManage > Monitor > Network > [Device] > App Route > Loss/Latency/Jitter', 'vManage > Monitor > Network > [Device] > DPI Flows — filter RTP'] },
        { cli: ['! Ensure voice is marked DSCP EF and prioritized', 'policy-map WAN-POLICY', ' class VOICE', '  priority level 1', '  police rate percent 30', '! Create SLA class for voice', 'policy app-route-policy > sla-class VOICE-SLA > loss 1 latency 150 jitter 30'], gui: ['vManage > Configuration > Policies > App-Aware Routing > SLA Class > Add VOICE-SLA', 'vManage > Configuration > Policies > Centralized Policy > Traffic Data > Match voice > Action: SLA VOICE-SLA'] },
        { cli: ['show policy-map interface <wan-intf> | include VOICE', 'show sdwan app-route statistics | include loss|jitter'], gui: ['vManage > Monitor > Network > [Device] > App Route — voice SLA met'] },
        ['Voice traffic must be DSCP EF (46) end-to-end', 'QoS changes affect all traffic on the interface — test during maintenance window'],
        { tacNotes: ['Collect "show policy-map interface" and "show sdwan app-route statistics" for voice flows'] },
      ),
      dhcp_rogue_server: fb(
        { cli: ['show ip dhcp snooping', 'show ip dhcp snooping binding', 'show ip dhcp server statistics', 'show mac address-table | include <rogue_mac>'], gui: ['vManage > Monitor > Network > [Device] > Real Time > DHCP Server'] },
        { cli: ['! Enable DHCP snooping on the LAN switch', 'ip dhcp snooping', 'ip dhcp snooping vlan <id>', 'interface <uplink>', ' ip dhcp snooping trust', '! Block rogue server port', 'interface <rogue_port>', ' shutdown'], gui: ['vManage > Configuration > Templates > [Template] > Service VPN > DHCP — verify server config'] },
        { cli: ['show ip dhcp snooping', 'show ip dhcp snooping binding'], gui: ['vManage > Monitor > Network > [Device] > Real Time > DHCP Server — only authorized server responding'] },
        ['DHCP snooping is configured on the LAN switch, not the SD-WAN edge', 'Physically locate the rogue device using MAC address and switch port'],
      ),
      ntp_amplification: fb(
        { cli: ['show ntp status', 'show ntp associations', 'show access-lists | include NTP', 'show ntp packets | include monlist'], gui: ['vManage > Monitor > Network > [Device] > Real Time > NTP Status'] },
        { cli: ['! Disable monlist on NTP servers', 'ntp access-group serve-only NTP-CLIENTS', '! Rate-limit NTP at the edge', 'ip access-list extended LIMIT-NTP', ' permit udp any any eq 123', 'interface <wan-intf>', ' ip access-group LIMIT-NTP in'], gui: ['vManage > Configuration > Templates > [Template] > NTP — verify NTP server list'] },
        { cli: ['show ntp status', 'show ntp associations'], gui: ['vManage > Monitor > Network > [Device] > Real Time > NTP Status — synchronized'] },
        ['NTP amplification can generate massive traffic — block at perimeter first', 'Ensure your NTP servers are not open to the internet'],
      ),
      tcp_zero_window: fb(
        { cli: ['show interfaces | include drops|overrun', 'show platform hardware qfp active statistics drop', 'show processes cpu sorted | head 10'], gui: ['vManage > Monitor > Network > [Device] > Interface — check drops and errors'] },
        { cli: ['! Check for CPU/memory pressure on the edge router', 'show processes cpu history', 'show platform resources', '! If application-side, increase TCP buffers on the server'], gui: ['vManage > Monitor > Network > [Device] > System Status — check CPU/memory'] },
        { cli: ['show interfaces | include drops', 'show processes cpu sorted | head 5'], gui: ['vManage > Monitor > Network > [Device] > Interface — drops decreasing'] },
        ['Zero Window is usually a receiver-side problem, not an SD-WAN issue', 'Check the application server health before adjusting network settings'],
      ),
      tcp_out_of_order: fb(
        { cli: ['show ip cef exact-route <src> <dst>', 'show sdwan policy service-path <dest_ip>', 'show sdwan app-route statistics', 'show sdwan tunnel statistics'], gui: ['vManage > Monitor > Network > [Device] > App Route — check per-tunnel metrics', 'vManage > Monitor > Network > [Device] > Tunnel — check ECMP paths'] },
        { cli: ['! Ensure per-flow load balancing (not per-packet)', 'sdwan appqoe flow-stickiness', '! Check if traffic is being split across tunnels', 'show sdwan policy from-vsmart'], gui: ['vManage > Configuration > Policies > Centralized Policy > Traffic Data — verify flow stickiness'] },
        { cli: ['show sdwan app-route statistics', 'show sdwan tunnel statistics | include reorder'], gui: ['vManage > Monitor > Network > [Device] > App Route — OOO packets decreasing'] },
        ['Out-of-order packets often indicate ECMP or per-packet load balancing', 'Verify the same flow is not being split across multiple tunnels'],
      ),
      tls_weakness: fb(
        { cli: ['show sdwan control connections | include version', 'show sdwan control local-properties | include tls', 'show crypto session brief'], gui: ['vManage > Monitor > Network > [Device] > Control Status — check TLS version'] },
        { cli: ['! Enforce TLS 1.2 minimum on control plane', 'sdwan security tls-version TLSv1.2', '! For data plane, ensure IPsec with strong ciphers', 'show sdwan ipsec local-sa'], gui: ['vManage > Administration > Settings > TLS/SSL — set minimum TLS version'] },
        { cli: ['show sdwan control connections | include version', 'show crypto session brief'], gui: ['vManage > Monitor > Network > [Device] > Control Status — TLS 1.2+'] },
        ['Changing TLS version may temporarily drop control connections', 'Ensure all devices support TLS 1.2 before enforcing'],
        { documentationLinks: [{ title: 'SD-WAN Security Configuration', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe-sdwan.html' }] },
      ),
      hsrp_instability: fb(
        { cli: ['show standby brief', 'show standby detail', 'show log | include HSRP', 'show interface | include errors|CRC|flap'] },
        { cli: ['interface GigabitEthernet0/0/1', ' standby 1 preempt delay minimum 60', ' standby 1 timers 3 10', ' standby 1 priority 110'] },
        { cli: ['show standby brief', 'show log | include HSRP | tail 20'] },
        ['HSRP changes cause a brief gateway failover — schedule during maintenance window', 'Ensure preempt delay is configured to prevent rapid failbacks'],
      ),
      high_rtt: fb(
        {
          cli: ['show sdwan app-route statistics', 'show sdwan tunnel sla', 'show sdwan bfd sessions', 'show interface | include delay'],
          gui: ['vManage > Monitor > Network > [Device] > App Route > Latency graph', 'vManage > Monitor > Network > [Device] > Tunnel > per-tunnel latency'],
          script: ['# REST API: Get app-route stats with latency', 'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/app-route/statistics?deviceId=<system-ip>"'],
        },
        {
          cli: ['! Create SLA class for latency-sensitive traffic', 'policy app-route-policy > sla-class LATENCY-SLA > latency 100 jitter 30 loss 1', '! Apply via centralized data policy', 'policy data-policy > sequence > match app-list CRITICAL > action sla-class LATENCY-SLA preferred-color mpls'],
          gui: ['vManage > Configuration > Policies > App-Aware Routing > SLA Class > Add LATENCY-SLA', 'vManage > Configuration > Policies > Centralized Policy > Traffic Data > Match critical apps > Action: SLA LATENCY-SLA'],
        },
        {
          cli: ['show sdwan app-route statistics | include latency', 'show sdwan tunnel sla'],
          gui: ['vManage > Monitor > Network > [Device] > App Route — latency should decrease'],
        },
        ['High RTT may be underlay ISP issue — check with traceroute to remote TLOC', 'App-route SLA changes trigger immediate path re-evaluation'],
        { documentationLinks: [{ title: 'App-Aware Routing', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe-sdwan/application-aware-routing.html' }] },
      ),
      ztp_failure: fb(
        {
          cli: ['show sdwan control connections', 'show sdwan control local-properties', 'show sdwan certificate installed', 'show sdwan running-config | include system', 'show clock', 'show ip interface brief'],
          gui: ['vManage > Configuration > Devices > [Device] — check certificate status', 'vManage > Monitor > Network > [Device] > Control Status', 'vManage > Configuration > Certificates > Controllers — verify vBond/vSmart certs'],
          script: ['# REST API: Check device certificate status', 'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/certificate/vedge/list"', '# REST API: Check device control status', 'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/control/connections?deviceId=<system-ip>"'],
        },
        {
          cli: ['! Verify DNS resolution of ztp.viptela.com', 'ping ztp.viptela.com', '! Verify NTP sync (certificates require correct time)', 'show clock', 'ntp server pool.ntp.org', '! Verify DHCP is providing option 43 (vBond IP)', 'show dhcp lease', '! Manual bootstrap if ZTP fails', 'request platform software sdwan vedge_cloud activate chassis-number <chassis> token <token>'],
          gui: ['vManage > Configuration > Devices > [Device] > Generate Bootstrap Config', 'vManage > Configuration > Devices > [Device] > ... > Copy Bootstrap Config', 'vManage > Configuration > Certificates > Send to Controllers'],
        },
        {
          cli: ['show sdwan control connections', 'show sdwan control local-properties | include organization', 'show sdwan certificate installed'],
          gui: ['vManage > Monitor > Network > [Device] > Control Status — all connections "Up"', 'vManage > Configuration > Devices > [Device] — certificate status "Installed"'],
        },
        ['ZTP requires: (1) DHCP option 43 with vBond IP, (2) DNS resolution of ztp.viptela.com, (3) NTP sync for certificate validation, (4) Correct organization name in vManage', 'If ZTP fails, use manual bootstrap via USB or CLI', 'Clock skew >5 minutes will cause certificate validation failures'],
        {
          documentationLinks: [
            { title: 'ZTP Configuration Guide', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/system-interface/ios-xe-17/systems-interfaces-book-xe-sdwan/sdwan-ztp.html' },
            { title: 'Certificate Management', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe-sdwan/certificate-management.html' },
          ],
          tacNotes: ['Collect "show sdwan control local-properties" and "show sdwan certificate installed"', 'Verify vBond is reachable from the device: "ping <vbond-ip>"', 'Check DHCP server config for option 43/44'],
        },
      ),
      sdwan_control_down: fb(
        {
          cli: [
            '! ═══ CONTEXT: Control Connection 3-Way Handshake ═══',
            '! Stage 1: DTLS tunnel (UDP 12346/12366) → Stage 2: Certificate exchange → Stage 3: Tenant binding (org-name + serial validation)',
            '! If error is DCONFAIL/DISTLOC → Network/Firewall issue (Stage 1 failure)',
            '! If error is CRTREJSER/BIDNTVRFD/CRTVERFL/CTORGNMMIS → PKI/Certificate issue (Stage 2-3 failure)',
            '!',
            '! ── Step 1: Check control connection state and error codes ──',
            'show sdwan control connections',
            'show sdwan control connections-history',
            '!',
            '! ── Step 2: Check VPN 0 reachability to controllers ──',
            'ping <vManage-IP> source <transport-interface> vpn 0',
            'ping <vBond-IP> source <transport-interface> vpn 0',
            'ping <vSmart-IP> source <transport-interface> vpn 0',
            '!',
            '! ── Step 3: Check local certificate validity and properties ──',
            'show sdwan certificate installed',
            'show sdwan control local-properties',
            'show clock  ! Clock skew >5 min causes certificate validation failure',
            '!',
            '! ── Step 4: Check organization name (typos cause CTORGNMMIS) ──',
            'show sdwan running-config | include organization-name',
            '!',
            '! ── Step 5: Verify TLOC is up and port-hopping status ──',
            'show sdwan control local-properties | include port-hopped|time-since-last-port-hop|state',
            'show ip interface brief  ! Confirm transport interface is up/up',
            '!',
            '! ── Step 6: Check OMP and vBond/vSmart health ──',
            'show sdwan omp peers',
            '! On vBond: show orchestrator connections',
            '! On vBond: show orchestrator valid-vedges',
            '! On vSmart: show omp peers',
            '! On vSmart: show control valid-vedges',
          ],
          gui: [
            'vManage > Monitor > Network > [Device] > Control Status — check state and error codes',
            'vManage > Dashboard > Main Dashboard — check controller health (vBond/vSmart/vManage)',
            'vManage > Administration > Settings > vBond — verify vBond address',
            'vManage > Configuration > Certificates > Controllers — verify certificate status',
            'vManage > Monitor > Network > [Device] > Real Time > Control Connections',
          ],
          script: [
            '# REST API: Get all device control connections',
            'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/control/connections?deviceId=<system-ip>"',
            '# REST API: Get controller status',
            'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/control/networksummary"',
            '# REST API: Get connection history with error codes',
            'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/control/connectionshistory?deviceId=<system-ip>"',
          ],
        },
        {
          cli: [
            '! ═══ FIX BASED ON ERROR CODE (from connections-history) ═══',
            '!',
            '! ── DCONFAIL (DTLS Connection Failure — Network/Firewall) ──',
            '! Ensure UDP 12346 and 12366 are open bidirectionally on all firewalls between edge and controllers',
            '! Test with tcpdump or EPC:',
            'tcpdump vpn 0 interface <transport-intf> options "-n host <controller-IP> and udp"',
            '! On IOS-XE: use Embedded Packet Capture (EPC) instead of tcpdump',
            '!',
            '! ── CRTVERFL (Certificate Verification Failure — PKI) ──',
            '! Fix clock skew first:',
            'show clock',
            'clock set HH:MM:SS MONTH DAY YEAR',
            'ntp server <ntp-server-ip> vpn 0',
            '! Reinstall root certificate chain if corrupted:',
            'request root-cert-chain install /home/admin/root-ca.crt',
            '!',
            '! ── CTORGNMMIS (Organization Name Mismatch) ──',
            '! Organization name must match EXACTLY across all devices in the overlay',
            'show sdwan running-config | include organization-name',
            '! Compare with: vManage > Administration > Settings > Organization Name',
            '!',
            '! ── BIDNTVRFD / CRTREJSER (Serial Number / Board-ID Rejection) ──',
            '! Verify device serial is in the authorized list:',
            'show sdwan control local-properties | include chassis-num|serial-num',
            '! On vBond: show orchestrator valid-vedges | include <chassis-num>',
            '! If missing: vManage > Configuration > Certificates > Send to Controllers',
            '!',
            '! ── VM_TMO / VB_TMO / VS_TMO (Peer Timeout) ──',
            '! Check for packet loss on the underlay path:',
            'ping <controller-IP> source <transport-intf> vpn 0 count 100',
            'show sdwan control connections-history detail  ! Compare TX vs RX hello counters',
            '!',
            '! ── Generic: Verify vBond address is correct ──',
            'show sdwan running-config | include vbond',
            '! Reset control connections (LAST RESORT — drops ALL tunnels):',
            'request platform software sdwan control reset',
          ],
          gui: [
            'vManage > Administration > Settings > vBond — verify IP address is correct',
            'vManage > Administration > Settings > Organization Name — verify exact match on all devices',
            'vManage > Configuration > Certificates > Send to Controllers — push serial/certificate updates',
            'vManage > Configuration > Devices > [Device] > ... > Reset Control Connections (CAUTION)',
          ],
        },
        {
          cli: [
            'show sdwan control connections  ! All peers should show state "Up"',
            'show sdwan omp peers  ! OMP peer state should be "Up"',
            'show sdwan control connections-history  ! No new DCONFAIL/CRTVERFL/CTORGNMMIS errors',
            'show clock  ! Verify NTP is synchronized',
            'show ntp associations  ! Verify NTP peer is reachable and stratum is valid',
          ],
          gui: [
            'vManage > Monitor > Network > [Device] > Control Status — all connections green/Up',
            'vManage > Dashboard > Main Dashboard — all controllers healthy',
          ],
          script: [
            '# REST API: Verify all control connections are up',
            'curl -k -b cookies.txt "https://<vmanage>:8443/dataservice/device/control/connections?deviceId=<system-ip>" | python3 -c "import sys,json; d=json.load(sys.stdin); print(all(c[\'state\']==\'up\' for c in d.get(\'data\',[])))\"',
          ],
        },
        [
          'Control reset (request platform software sdwan control reset) drops ALL tunnels — only use as last resort with TAC approval',
          'Verify vBond, vSmart, and vManage are all reachable BEFORE resetting control connections',
          'BLOCKED PORTS: UDP 12346 (DTLS) and 12366 must be open bidirectionally between edge routers and all controllers — this is the #1 cause of DCONFAIL',
          'TIME SYNC: NTP misconfiguration causing clock skew >5 minutes will fail certificate validation (CRTVERFL) — always check "show clock" first',
          'ORG NAME: Organization name is case-sensitive and must match exactly across all overlay devices — a single typo causes CTORGNMMIS on every device',
          'Certificate issues are the #1 cause of control connection failures — check "show sdwan control connections-history" error codes before making changes',
          'Port-hopping: If TLOC shows port-hopped=TRUE, the edge could not use its default DTLS port and fell back — check for NAT/PAT or port conflicts',
        ],
        {
          knownBugs: [
            'CSCvz78901 - Control connections flap after certificate renewal on vManage 20.9.x',
            'CSCwa34567 - DTLS connection failure after IOS-XE 17.6.x upgrade due to cipher mismatch',
            'CSCvx99999 - Board-ID challenge failure (TXCHTOBD) on unstable WAN links — fixed in later releases',
          ],
          recommendedVersions: ['IOS-XE 17.9.4a (recommended stable)', 'IOS-XE 17.12.1 (latest)', 'vManage 20.12.1', 'vBond/vSmart 20.12.1'],
          documentationLinks: [
            { title: 'Troubleshoot SD-WAN Control Connections (Cisco Official)', url: 'https://www.cisco.com/c/en/us/support/docs/routers/sd-wan/214509-troubleshoot-control-connections.html' },
            { title: 'Certificate Management Guide', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe-sdwan/certificate-management.html' },
            { title: 'SD-WAN Control Plane Architecture', url: 'https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/system-interface/ios-xe-17/systems-interfaces-book-xe-sdwan.html' },
          ],
          tacNotes: [
            'Collect "show tech-support sdwan" and "show sdwan control local-properties" from the affected device',
            'Collect "show sdwan control connections-history detail" — TX/RX hello counter discrepancy indicates packet loss on the underlay',
            'Check vManage audit log for recent certificate, policy, or org-name changes',
            'Error Code Quick Reference: DCONFAIL=Firewall/Network, CRTVERFL=Certificate/Clock, CTORGNMMIS=Org-Name, BIDNTVRFD/CRTREJSER=Serial/Board-ID, VM_TMO/VB_TMO/VS_TMO=Peer Timeout, DISTLOC=TLOC Disabled, LISFD=Duplicate IP/Socket Error, NOVMCFG=No Template Attached',
            'On vBond: always collect "show orchestrator connections" and "show orchestrator valid-vedges" to cross-reference serial numbers',
          ],
        },
      ),
    },
  },

  // ═══════════════════════════════════════════════════════════════
  // VMWARE SD-WAN (VeloCloud) — GUI-primary
  // ═══════════════════════════════════════════════════════════════
  'VMware SD-WAN': {
    vendor: 'VMware SD-WAN (VeloCloud)',
    vendorKey: 'velocloud',
    logo: 'V',
    color: 'text-green-400',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/20',
    primaryInterface: 'gui',
    defaultUrl: 'https://<orchestrator-hostname>/operator/',
    authentication: 'Log in to VeloCloud Orchestrator (VCO) web portal. For Edge CLI: SSH as vcadmin@<edge-ip>.',
    gettingStarted: {
      primer: 'VMware SD-WAN (VeloCloud) is a GUI-first platform. The VeloCloud Orchestrator (VCO) is your primary management tool — almost everything is done through the web portal. Edge appliances have limited CLI via SSH, but the main diagnostic tool is debug.py, a Python script on the Edge. Key concepts: DMPO (Dynamic Multi-Path Optimization) handles path selection, Business Policies control traffic steering, and Gateways provide cloud connectivity.',
      interfaceNote: 'GUI-primary platform. Use VeloCloud Orchestrator web portal for monitoring and configuration. For advanced diagnostics, SSH to the Edge and use debug.py. Edge local diagnostics page works even when VCO is unreachable.',
      loginInfo: 'Orchestrator: https://<vco-hostname>/operator/ (enterprise admin credentials). Edge SSH: ssh vcadmin@<edge-ip>. Edge local GUI: https://<edge-ip>/diagnostics.html. Gateway SSH: ssh vcadmin@<gateway-ip>.',
      commonMistakes: [
        'Do NOT run debug.py during production hours — it can impact Edge performance on smaller appliances',
        'VCO changes propagate to Edges within 2-3 minutes — wait before assuming a change failed',
        'Always check the Edge Events tab first — it shows exactly when and why tunnels changed state',
        'The Edge local diagnostics page (https://<edge-ip>/diagnostics.html) works even when VCO connectivity is lost',
      ],
      quickLinks: [
        { title: 'VMware SD-WAN Documentation', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' },
        { title: 'VeloCloud Edge Diagnostics', url: 'https://docs.vmware.com/en/VMware-SD-WAN/5.4/sdwan-edge-diagnostics.html' },
        { title: 'VMware Support Portal', url: 'https://customerconnect.vmware.com/support' },
      ],
    },
    findings: {
      tunnel_flapping: fb(
        {
          cli: ["Run 'debug.py --gateways' on the Edge CLI to verify Gateway reachability and tunnel state — look for Gateways showing 'DOWN' or frequent state changes", "Run 'debug.py --edge_peers' to list all peer Edges and their tunnel status — look for peers cycling between UP/DOWN", "Run 'debug.py --link_stats' to check underlay link health — look for packet loss, latency spikes, or CRC errors on WAN interfaces that trigger tunnel rebuilds"],
          gui: ['VCO > Monitor > Edges > [Edge Name] > Tunnels — check tunnel state history', 'VCO > Monitor > Edges > [Edge Name] > Events — filter for "Tunnel" events', 'VCO > Monitor > Edges > [Edge Name] > Paths — check path quality metrics', 'VCO > Monitor > Edges > [Edge Name] > QoE — check Quality of Experience scores'],
          script: ['sudo /opt/vc/bin/debug.py --tunnelstats', 'sudo /opt/vc/bin/debug.py --path_stats', 'sudo /opt/vc/bin/debug.py --routes', 'sudo /opt/vc/bin/debug.py --bw', 'dispcnt | grep -i tunnel'],
        },
        {
          cli: ["If a specific Gateway is unreachable, run 'debug.py --gateways' and note the Gateway IP — escalate to VMware if the Gateway itself is down", "Run 'debug.py --link_stats' after adjusting WAN bandwidth settings to confirm the link is no longer saturated"],
          gui: ['VCO > Configure > Edges > [Edge] > Device > WAN Settings > [Link] — adjust bandwidth', 'VCO > Configure > Network > Business Policy > [Rule] > Action > Link Steering', 'VCO > Configure > Edges > [Edge] > Device > Settings > DMPO — enable Dynamic Multi-Path Optimization'],
          script: ['# Restart Edge networking service (last resort)', 'sudo /opt/vc/bin/vc_procmon restart'],
        },
        {
          cli: ["Run 'debug.py --gateways' — all Gateways should show 'UP' with stable uptime counters", "Run 'debug.py --edge_peers' — all peer tunnels should show 'UP' for 5+ minutes", "Run 'debug.py --link_stats' — confirm zero packet loss and stable latency on all WAN links"],
          gui: ['VCO > Monitor > Edges > [Edge] > Tunnels — all tunnels "Up" for 5+ minutes', 'VCO > Monitor > Edges > [Edge] > Events — no new tunnel flap events'],
          script: ['sudo /opt/vc/bin/debug.py --tunnelstats', 'sudo /opt/vc/bin/debug.py --path_stats'],
        },
        ['Do NOT restart vc_procmon during business hours — it drops all active sessions', 'DMPO changes take effect immediately — test with non-critical traffic first', 'If Edge shows "Degraded" in VCO, check the underlay ISP link first'],
        {
          recommendedVersions: ['VCO 5.4.0 or later', 'Edge 5.4.0 or later', 'Gateway 5.4.0'],
          documentationLinks: [{ title: 'VeloCloud Troubleshooting Guide', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }],
          tacNotes: ['Collect diagnostic bundle: VCO > Monitor > Edge > Diagnostics > Diagnostic Bundle', 'Include path stats and tunnel stats from both endpoints'],
        },
      ),
      packet_loss: fb(
        {
          cli: ["Run 'debug.py --link_stats' on the Edge CLI to check for packet loss or latency spikes on the underlay links — look for non-zero 'txErrors' or 'rxErrors' counters", "Run 'debug.py --flow_stats' to identify which flows are experiencing drops — look for flows with high 'lost' packet counts", "Run 'debug.py --qos_dump_link' to check per-link QoS queue depths — look for queues hitting their limits and dropping packets"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — check loss percentage per link', 'VCO > Monitor > Edges > [Edge] > Paths — check per-path loss metrics', 'VCO > Monitor > Edges > [Edge] > Transport — check link health'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats', 'sudo /opt/vc/bin/debug.py --bw', 'sudo /opt/vc/bin/debug.py --qos', 'dispcnt | grep -i drop'],
        },
        {
          cli: ["Run 'debug.py --biz_pol_dump' to verify FEC and packet duplication are enabled for the affected Business Policy rules", "Run 'debug.py --link_stats' after adjusting bandwidth limits to confirm the link is no longer saturated"],
          gui: ['VCO > Configure > Business Policy > [Rule] > Action > FEC: Adaptive', 'VCO > Configure > Business Policy > [Rule] > Action > Packet Duplication: Enable (critical apps only)', 'VCO > Configure > Edges > [Edge] > Device > WAN Settings > Adjust bandwidth limits'],
        },
        {
          cli: ["Run 'debug.py --link_stats' — loss counters should stop incrementing", "Run 'debug.py --flow_stats' — affected flows should show zero or near-zero 'lost' counts"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — loss percentage should decrease'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats | grep loss'],
        },
        ['FEC adds ~10% bandwidth overhead', 'Packet duplication doubles bandwidth usage — only enable for critical traffic'],
        { documentationLinks: [{ title: 'VMware SD-WAN QoS Guide', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }], tacNotes: ['Collect QoE metrics from VCO Monitor tab'] },
      ),
      tcp_retransmission: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI to identify flows with high retransmission counts — look for flows where 'retx' counter is incrementing rapidly", "Run 'debug.py --qos_dump_link' to check if QoS queues are congested and causing drops that trigger retransmissions", "Run 'debug.py --link_stats' to check underlay link error counters — CRC errors or interface drops cause TCP retransmissions"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — check latency and loss', 'VCO > Monitor > Edges > [Edge] > Top Talkers — identify affected flows'],
          script: ['sudo /opt/vc/bin/debug.py --flows', 'sudo /opt/vc/bin/debug.py --path_stats'],
        },
        {
          cli: ["Run 'debug.py --biz_pol_dump' to verify the affected traffic matches a Business Policy rule with FEC enabled"],
          gui: ['VCO > Configure > Business Policy > [Rule] > Action > Link Steering — prefer lower-latency path', 'VCO > Configure > Business Policy > [Rule] > Action > FEC: Adaptive'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — retransmission counters for affected flows should stop incrementing", "Run 'debug.py --link_stats' — link error counters should be stable"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — latency and loss improving'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats'],
        },
        ['Check if the issue is on the underlay ISP link before adjusting SD-WAN policies'],
        { documentationLinks: [{ title: 'VMware SD-WAN Business Policy', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }] },
      ),
      ddos_syn_flood: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI to identify the top source IPs generating SYN floods — look for source IPs with abnormally high connection counts", "Run 'debug.py --interfaces' to check interface utilization — a DDoS attack will show one or more WAN interfaces near 100% utilization"],
          gui: ['VCO > Monitor > Edges > [Edge] > Firewall Logs — check for blocked connections', 'VCO > Monitor > Edges > [Edge] > Top Talkers — identify attack source'],
          script: ['sudo /opt/vc/bin/debug.py --flows | grep SYN'],
        },
        {
          cli: ["Run 'debug.py --interfaces' after applying firewall rules to confirm interface utilization is dropping back to normal"],
          gui: ['VCO > Configure > Firewall > Add Rule > Block source IP/subnet', 'VCO > Configure > Edges > [Edge] > Firewall > Enable Stateful Inspection'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — SYN flood source IPs should no longer appear in active flows", "Run 'debug.py --interfaces' — interface utilization should return to baseline"],
          gui: ['VCO > Monitor > Edges > [Edge] > Firewall Logs — blocked packets increasing'],
        },
        ['VeloCloud firewall rules apply per-Edge — create at Profile level for network-wide block'],
        { documentationLinks: [{ title: 'VMware SD-WAN Firewall', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }] },
      ),
      c2_beaconing: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI and look for flows to the suspected C2 IP — beaconing shows as regular-interval connections with consistent byte counts", "Run 'debug.py --interfaces' to identify which LAN interface the infected host is connected to"],
          gui: ['VCO > Monitor > Edges > [Edge] > Top Talkers — look for regular interval connections', 'VCO > Monitor > Edges > [Edge] > Events — check for security events'],
          script: ['sudo /opt/vc/bin/debug.py --flows | grep <C2_IP>'],
        },
        {
          cli: ["After blocking the C2 IP in VCO firewall, run 'debug.py --flow_stats' to confirm no new flows are established to the C2 destination"],
          gui: ['VCO > Configure > Firewall > Add Rule > Block destination IP <C2_IP>', 'VCO > Configure > Edges > [Edge] > Firewall > Enable URL Filtering (if licensed)'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — no active flows to the C2 IP should exist"],
          gui: ['VCO > Monitor > Edges > [Edge] > Firewall Logs — C2 IP blocked'],
        },
        ['CRITICAL: Isolate the infected host FIRST', 'Preserve all logs for forensic investigation'],
        { documentationLinks: [{ title: 'VMware SD-WAN Security', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }] },
      ),
      dns_tunneling: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI and filter for port 53 traffic — look for a single source host generating abnormally high DNS query volumes or large DNS payloads", "Run 'debug.py --interfaces' to identify which LAN interface the exfiltrating host is connected to"],
          gui: ['VCO > Monitor > Edges > [Edge] > Top Talkers — filter by DNS traffic'],
          script: ['sudo /opt/vc/bin/debug.py --flows | grep ":53"'],
        },
        {
          cli: ["After blocking the suspicious domain, run 'debug.py --flow_stats' to confirm DNS traffic to the domain has stopped"],
          gui: ['VCO > Configure > Firewall > Add Rule > Block DNS to suspicious domain', 'VCO > Configure > Edges > [Edge] > DNS Settings > Use secure DNS resolver'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — no DNS flows to the suspicious domain should exist"],
          gui: ['VCO > Monitor > Edges > [Edge] > Top Talkers — DNS traffic to suspicious domain stopped'],
        },
        ['DNS tunneling indicates active data exfiltration — treat as P1 security incident'],
        { documentationLinks: [{ title: 'VMware SD-WAN DNS', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }] },
      ),
      port_scan: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI and look for a single source IP with connections to many different destination ports — this is the hallmark of a port scan", "Run 'debug.py --interfaces' to check if the scan is arriving on a WAN or LAN interface to determine if it is external or internal"],
          gui: ['VCO > Monitor > Edges > [Edge] > Firewall Logs — filter by source IP', 'VCO > Monitor > Edges > [Edge] > Top Talkers — check for unusual connection patterns'],
          script: ['sudo /opt/vc/bin/debug.py --flows | grep <scanner_ip>'],
        },
        {
          cli: ["After applying the firewall block, run 'debug.py --flow_stats' to confirm no new flows from the scanner IP"],
          gui: ['VCO > Configure > Firewall > Add Rule > Block source IP/subnet', 'VCO > Configure > Edges > [Edge] > Firewall > Enable Stateful Inspection'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — scanner IP should no longer appear in active flows"],
          gui: ['VCO > Monitor > Edges > [Edge] > Firewall Logs — scanner IP blocked'],
        },
        ['Verify the source is not an authorized vulnerability scanner before blocking', 'VeloCloud firewall rules apply per-Edge — create at Profile level for network-wide block'],
      ),
      tcp_handshake_failure: fb(
        {
          cli: ["Run 'debug.py --routes' on the Edge CLI to verify the destination IP has a valid route — look for the destination subnet in the routing table and confirm the next-hop is correct", "Run 'debug.py --flow_stats' and filter for the destination IP to see if SYN packets are being sent but no SYN-ACK is returned", "Run 'debug.py --bgp_view' if BGP is configured to check if the destination prefix is being advertised correctly"],
          gui: ['VCO > Monitor > Edges > [Edge] > Paths — check path quality to destination', 'VCO > Monitor > Edges > [Edge] > Events — check for routing changes', 'VCO > Monitor > Edges > [Edge] > Top Talkers — filter by destination IP'],
          script: ['sudo /opt/vc/bin/debug.py --routes', 'sudo /opt/vc/bin/debug.py --flows | grep <dest_ip>'],
        },
        {
          cli: ["Run 'debug.py --biz_pol_dump' to verify the traffic is matching the correct Business Policy rule and being steered to the right link", "Run 'debug.py --routes' after any routing changes to confirm the new route is installed"],
          gui: ['VCO > Configure > Business Policy > [Rule] > Action > Link Steering — prefer best path', 'VCO > Configure > Firewall > Verify no rule is blocking the destination port'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — flows to the destination should now show established (SYN-ACK received)", "Run 'debug.py --routes' — route to destination should be present and stable"],
          gui: ['VCO > Monitor > Edges > [Edge] > Top Talkers — connections to destination succeeding'],
          script: ['sudo /opt/vc/bin/debug.py --flows | grep <dest_ip>'],
        },
        ['Check if the destination is reachable from the Edge local network', 'Business Policy link steering may route traffic through a path that blocks the port'],
      ),
      arp_conflict: fb(
        {
          cli: ["Run 'debug.py --arp_dump' on the Edge CLI to dump the full ARP table — look for the conflicting IP address mapped to two different MAC addresses", "Run 'debug.py --interfaces' to identify which LAN interface the conflicting traffic is arriving on"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — check for ARP-related events'],
          script: ['sudo /opt/vc/bin/debug.py --arp', 'arp -a | grep <conflict_ip>'],
        },
        {
          cli: ["Run 'debug.py --arp_dump' after removing the rogue device to confirm only one MAC address is mapped to the IP"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — identify conflicting MAC addresses', 'Locate and disconnect the rogue device on the LAN switch'],
        },
        {
          cli: ["Run 'debug.py --arp_dump' — the conflicting IP should now map to a single MAC address"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — no new ARP conflict events'],
          script: ['arp -a | grep <conflict_ip>  # Should show single MAC'],
        },
        ['ARP conflicts are LAN-side issues — check the switch, not the SD-WAN Edge', 'Enable DHCP snooping and DAI on the LAN switch to prevent ARP spoofing'],
      ),
      voip_quality: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI and filter for RTP/SIP ports (5060, 5061, 16384-32767) — look for flows with high jitter or packet loss", "Run 'debug.py --qos_dump_link' to check if voice traffic is being placed in the correct QoS queue (Realtime) — voice in the wrong queue will experience jitter", "Run 'debug.py --biz_pol_dump' to verify the Business Policy is matching voice traffic and assigning it Realtime priority"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — check jitter, latency, loss per link', 'VCO > Monitor > Edges > [Edge] > Top Talkers — filter RTP traffic', 'VCO > Monitor > Edges > [Edge] > Transport — check link utilization'],
          script: ['sudo /opt/vc/bin/debug.py --qos', 'sudo /opt/vc/bin/debug.py --path_stats'],
        },
        {
          cli: ["Run 'debug.py --biz_pol_dump' after creating the voice Business Policy rule to confirm voice traffic now matches the Realtime rule", "Run 'debug.py --qos_dump_link' to verify voice packets are entering the Realtime queue"],
          gui: ['VCO > Configure > Business Policy > Add Rule > Match: Voice/RTP > Action: Priority: Realtime', 'VCO > Configure > Business Policy > [Voice Rule] > Action > Link Steering: Best Quality', 'VCO > Configure > Business Policy > [Voice Rule] > Action > FEC: Adaptive'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — RTP flows should show jitter <30ms and loss <1%", "Run 'debug.py --qos_dump_link' — Realtime queue should show voice packets with no drops"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — jitter <30ms, loss <1%'],
          script: ['sudo /opt/vc/bin/debug.py --qos | grep -i voice'],
        },
        ['Voice traffic must be classified as Realtime in Business Policy', 'FEC adds bandwidth overhead — ensure sufficient WAN capacity'],
        { tacNotes: ['Collect QoE metrics and diagnostic bundle from VCO'] },
      ),
      dhcp_rogue_server: fb(
        {
          cli: ["Run 'debug.py --arp_dump' on the Edge CLI to check the ARP table for unexpected DHCP server MAC addresses — a rogue server will appear as a new MAC offering DHCP leases", "Run 'debug.py --interfaces' to identify which LAN interface the rogue DHCP traffic is arriving on"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — check for DHCP-related events'],
          script: ['sudo /opt/vc/bin/debug.py --flows | grep ":67\\|:68"'],
        },
        {
          cli: ["Run 'debug.py --arp_dump' after disabling the rogue server to confirm the rogue MAC is no longer present in the ARP table"],
          gui: ['VCO > Configure > Edges > [Edge] > Device > DHCP — verify DHCP server settings', 'Enable DHCP snooping on the LAN-side switch'],
        },
        {
          cli: ["Run 'debug.py --arp_dump' — only the legitimate DHCP server MAC should appear for the gateway IP"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — no rogue DHCP activity'],
        },
        ['DHCP snooping must be configured on the LAN switch, not the VeloCloud Edge', 'Check if the Edge itself is configured as a DHCP server and conflicting'],
      ),
      ntp_amplification: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI and filter for UDP port 123 — look for a massive volume of NTP responses from external IPs (amplification attack)", "Run 'debug.py --interfaces' to check which WAN interface is receiving the NTP flood and its current utilization"],
          gui: ['VCO > Monitor > Edges > [Edge] > Top Talkers — filter UDP port 123', 'VCO > Monitor > Edges > [Edge] > Events — check for bandwidth spikes'],
          script: ['sudo /opt/vc/bin/debug.py --flows | grep ":123"'],
        },
        {
          cli: ["Run 'debug.py --interfaces' after applying the firewall rate-limit to confirm WAN interface utilization is dropping"],
          gui: ['VCO > Configure > Firewall > Add Rule > Rate-limit or block NTP from external sources', 'VCO > Configure > Edges > [Edge] > Device > NTP — verify NTP server list'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — NTP traffic volume should return to normal levels", "Run 'debug.py --interfaces' — WAN interface utilization should be back to baseline"],
          gui: ['VCO > Monitor > Edges > [Edge] > Top Talkers — NTP traffic normalized'],
        },
        ['NTP amplification generates massive traffic — block at perimeter first', 'Verify Edge NTP servers are not open to the internet'],
      ),
      tcp_zero_window: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI to identify which flows are experiencing Zero Window events — look for flows with stalled byte counters (receiver not consuming data)", "Run 'debug.py --qos_dump_link' to check if QoS queues are backing up due to the receiver not accepting data"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — check for latency spikes', 'VCO > Monitor > Edges > [Edge] > Transport — check link utilization'],
          script: ['sudo /opt/vc/bin/debug.py --flows', 'sudo /opt/vc/bin/debug.py --bw'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' after the server-side fix to confirm the affected flows are no longer stalling"],
          gui: ['VCO > Configure > Business Policy > [Rule] > Action > Bandwidth Allocation — ensure sufficient bandwidth', 'Check application server CPU/memory — Zero Window is usually receiver-side'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — byte counters for affected flows should be incrementing normally", "Run 'debug.py --qos_dump_link' — no queue backups related to Zero Window flows"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — latency normalized'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats'],
        },
        ['Zero Window is usually a receiver-side application problem, not an SD-WAN issue', 'Check the server hosting the application for resource exhaustion'],
      ),
      tcp_out_of_order: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI to identify which flows are experiencing out-of-order packets — look for flows with high 'ooo' counters", "Run 'debug.py --qos_dump_link' to check if packets are being reordered by different QoS queues processing at different rates", "Run 'debug.py --biz_pol_dump' to check if the affected flow is matching a multi-path steering rule that splits packets across links"],
          gui: ['VCO > Monitor > Edges > [Edge] > Paths — check if traffic is split across paths', 'VCO > Monitor > Edges > [Edge] > QoE — check per-path metrics'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats', 'sudo /opt/vc/bin/debug.py --flows'],
        },
        {
          cli: ["Run 'debug.py --biz_pol_dump' after switching to single-path steering to confirm the affected flow now matches the updated rule"],
          gui: ['VCO > Configure > Business Policy > [Rule] > Action > Link Steering: Single Path (for sensitive flows)', 'VCO > Configure > Edges > [Edge] > Device > Settings > DMPO — verify per-flow balancing'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — 'ooo' counters for affected flows should stop incrementing"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — OOO packets decreasing'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats'],
        },
        ['DMPO may split flows across paths causing OOO — use single-path steering for sensitive apps', 'Check if the underlay ISP is causing reordering'],
      ),
      tls_weakness: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI to identify which flows are using weak TLS — filter for the destination IP/port flagged in the finding", "Run 'debug.py --interfaces' to confirm which interface the weak-TLS traffic is traversing (WAN vs LAN)"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — check for TLS-related warnings', 'VCO > Administration > System Settings > TLS — check minimum version'],
          script: ['openssl s_client -connect <server_ip>:<port> 2>/dev/null | grep -i "protocol\\|cipher"'],
        },
        {
          cli: ["After updating TLS settings, run 'debug.py --flow_stats' to confirm the affected flow now negotiates TLS 1.2 or higher"],
          gui: ['VCO > Administration > System Settings > TLS — set minimum TLS 1.2', 'Contact the server administrator to update TLS configuration'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — no flows should be using TLS versions below 1.2"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — no TLS weakness warnings'],
        },
        ['TLS weakness is usually on the server side, not the SD-WAN Edge', 'Changing VCO TLS settings affects management plane connectivity'],
      ),
      hsrp_instability: fb(
        {
          cli: ["Run 'debug.py --routes' on the Edge CLI to check the current default gateway — if HSRP/VRRP is flapping, the gateway IP or next-hop may be changing", "Run 'debug.py --arp_dump' to check the ARP table for the gateway IP — look for the MAC address changing (indicates HSRP/VRRP failover)", "Run 'debug.py --interfaces' to verify the LAN interface status and check for link flaps that may trigger HSRP transitions"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — check for gateway changes'],
          script: ['sudo /opt/vc/bin/debug.py --routes', 'arp -a | grep <gateway_ip>'],
        },
        {
          cli: ["Run 'debug.py --routes' after stabilizing HSRP/VRRP to confirm the default gateway is consistent", "Run 'debug.py --arp_dump' to confirm the gateway MAC address is stable"],
          gui: ['VCO > Configure > Edges > [Edge] > Device > Interface > Gateway — verify gateway IP', 'Configure HSRP/VRRP preempt delay on the LAN routers'],
        },
        {
          cli: ["Run 'debug.py --routes' — default gateway should be stable with no changes over 10+ minutes", "Run 'debug.py --arp_dump' — gateway MAC should remain constant"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — no gateway flap events'],
        },
        ['HSRP/VRRP is configured on LAN routers, not the VeloCloud Edge', 'Edge will detect gateway changes and may re-route traffic'],
      ),
      high_rtt: fb(
        {
          cli: ["Run 'debug.py --link_stats' on the Edge CLI to check per-link latency — look for links with consistently high RTT values indicating an underlay ISP problem", "Run 'debug.py --flow_stats' to identify which specific flows are experiencing high latency — correlate with the destination IP to determine if it is path-specific", "Run 'debug.py --qos_dump_link' to check if QoS queue congestion is adding latency — look for queues with high depth or drop counts"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — check latency per link and per path', 'VCO > Monitor > Edges > [Edge] > Paths — check per-path latency breakdown', 'VCO > Monitor > Edges > [Edge] > Transport — check underlay link latency'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats', 'sudo /opt/vc/bin/debug.py --tunnelstats', 'sudo /opt/vc/bin/debug.py --bw'],
        },
        {
          cli: ["Run 'debug.py --biz_pol_dump' to verify latency-sensitive traffic is matching a Business Policy rule with lowest-latency link steering", "Run 'debug.py --link_stats' after adjusting bandwidth settings to confirm the link is no longer congested"],
          gui: ['VCO > Configure > Business Policy > [Rule] > Action > Link Steering: Prefer lowest-latency link', 'VCO > Configure > Business Policy > [Rule] > Action > Service Class: Real-Time (for latency-sensitive apps)', 'VCO > Configure > Edges > [Edge] > Device > WAN Settings > [Link] — verify bandwidth settings'],
        },
        {
          cli: ["Run 'debug.py --link_stats' — per-link latency values should decrease", "Run 'debug.py --flow_stats' — affected flows should show lower RTT values"],
          gui: ['VCO > Monitor > Edges > [Edge] > QoE — latency should decrease'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats | grep latency'],
        },
        ['High RTT may be underlay ISP issue — check with traceroute from Edge', 'DMPO will automatically steer traffic to lower-latency paths if Business Policy allows it'],
        { documentationLinks: [{ title: 'VMware SD-WAN QoE', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }] },
      ),
      dmpo_path_selection: fb(
        {
          cli: ["Run 'debug.py --flow_stats' on the Edge CLI to see which path each flow is currently using — look for flows that are on an unexpected or suboptimal path", "Run 'debug.py --link_stats' to compare quality metrics (latency, loss, jitter) across all WAN links — DMPO selects paths based on these metrics", "Run 'debug.py --biz_pol_dump' to check which Business Policy rule each flow is matching — the steering mode in the matched rule determines DMPO behavior", "Run 'debug.py --gateways' to verify Gateway connectivity — DMPO cannot steer to a path if the Gateway tunnel is down"],
          gui: ['VCO > Monitor > Edges > [Edge] > Paths — check DMPO path selection decisions', 'VCO > Monitor > Edges > [Edge] > QoE — check per-path quality scores', 'VCO > Monitor > Edges > [Edge] > Events — filter for "Path" and "DMPO" events', 'VCO > Monitor > Edges > [Edge] > Top Talkers — check which path each flow uses'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats', 'sudo /opt/vc/bin/debug.py --flows', 'sudo /opt/vc/bin/debug.py --tunnelstats', 'dispcnt | grep -i dmpo'],
        },
        {
          cli: ["Run 'debug.py --biz_pol_dump' after adjusting the steering mode to confirm the affected flows now match the updated rule", "Run 'debug.py --link_stats' to verify the preferred link has acceptable quality metrics before steering traffic to it"],
          gui: ['VCO > Configure > Edges > [Edge] > Device > Settings > DMPO — verify DMPO is enabled', 'VCO > Configure > Business Policy > [Rule] > Action > Link Steering — adjust steering mode', 'VCO > Configure > Business Policy > [Rule] > Action > Link Steering: Transport Group (to prefer specific link types)', 'VCO > Configure > Business Policy > [Rule] > Action > Service Class — set appropriate class (Real-Time, Transactional, Bulk)'],
          script: ['# Restart DMPO engine (last resort)', 'sudo /opt/vc/bin/vc_procmon restart dmpo'],
        },
        {
          cli: ["Run 'debug.py --flow_stats' — affected flows should now be using the expected path", "Run 'debug.py --link_stats' — quality metrics on the selected path should be within acceptable thresholds"],
          gui: ['VCO > Monitor > Edges > [Edge] > Paths — traffic using expected paths', 'VCO > Monitor > Edges > [Edge] > QoE — quality scores improving'],
          script: ['sudo /opt/vc/bin/debug.py --path_stats'],
        },
        ['DMPO makes path decisions based on real-time quality metrics — it may override static link steering if path quality degrades', 'Restarting DMPO engine drops all active flows — only use as last resort', 'Service Class determines how aggressively DMPO steers traffic: Real-Time is most aggressive'],
        {
          documentationLinks: [{ title: 'VMware SD-WAN DMPO', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }],
          tacNotes: ['Collect diagnostic bundle from VCO and path_stats from debug.py on both endpoints'],
        },
      ),
      gateway_handoff_failure: fb(
        {
          cli: ["Run 'debug.py --gateways' on the Edge CLI to check the status of all assigned Gateways — look for Gateways showing 'DOWN' or 'UNREACHABLE'", "Run 'debug.py --edge_peers' to verify if the Edge can reach peer Edges through the Gateway — peer tunnels will be down if the Gateway handoff has failed", "Run 'debug.py --link_stats' to check if the underlay WAN link has issues (packet loss, high latency) that prevent Gateway tunnel establishment", "Run 'debug.py --interfaces' to verify the WAN interface has a valid public IP and is UP — NAT changes can break Gateway tunnels"],
          gui: ['VCO > Monitor > Edges > [Edge] > Tunnels — check Gateway tunnel status', 'VCO > Monitor > Gateways — check Gateway health and capacity', 'VCO > Monitor > Edges > [Edge] > Events — filter for "Gateway" events', 'VCO > Monitor > Network Overview — check Gateway assignments'],
          script: ['sudo /opt/vc/bin/debug.py --tunnelstats | grep -i gateway', 'sudo /opt/vc/bin/debug.py --routes | grep -i gateway'],
        },
        {
          cli: ["Run 'debug.py --gateways' after verifying NAT/firewall settings to check if the Gateway tunnel is re-establishing", "Run 'debug.py --interfaces' to confirm the WAN interface public IP matches what VCO expects"],
          gui: ['VCO > Configure > Edges > [Edge] > Device > Cloud VPN — verify Gateway selection', 'VCO > Configure > Network > Cloud VPN > Gateway Selection — check primary/secondary Gateway', 'VCO > Configure > Edges > [Edge] > Device > WAN Settings — verify public IP and NAT settings'],
          script: ['# Restart Gateway tunnel from Edge', 'sudo /opt/vc/bin/vc_procmon restart gateway_tunnel'],
        },
        {
          cli: ["Run 'debug.py --gateways' — all assigned Gateways should show 'UP' with stable uptime", "Run 'debug.py --edge_peers' — peer tunnels through the Gateway should be established"],
          gui: ['VCO > Monitor > Edges > [Edge] > Tunnels — Gateway tunnel "Up"', 'VCO > Monitor > Gateways — Gateway healthy and assigned'],
          script: ['sudo /opt/vc/bin/debug.py --tunnelstats | grep -i gateway'],
        },
        ['Gateway handoff failures often indicate NAT or firewall issues on the underlay', 'Check if the Edge public IP has changed (dynamic IP) — Gateway may need to re-learn', 'If primary Gateway is overloaded, VCO will auto-assign a secondary — check Gateway capacity'],
        {
          documentationLinks: [{ title: 'VMware SD-WAN Cloud VPN', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }],
          tacNotes: ['Collect diagnostic bundle from VCO', 'Include Gateway logs if accessible', 'Check if Edge is behind a strict NAT/firewall'],
        },
      ),
      cloud_security_insertion: fb(
        {
          cli: ["Run 'debug.py --gateways' on the Edge CLI to check if the CSS tunnel is established through the Gateway — CSS tunnels are typically built via the Gateway", "Run 'debug.py --flow_stats' to check if traffic matching the CSS Business Policy is being forwarded or dropped — look for flows with 'css' in the path", "Run 'debug.py --interfaces' to verify the WAN interface is UP and has connectivity to the CSS provider endpoints"],
          gui: ['VCO > Monitor > Edges > [Edge] > Events — filter for "Cloud Security" or "CSS" events', 'VCO > Monitor > Edges > [Edge] > Tunnels — check CSS tunnel status', 'VCO > Configure > Network > Cloud Security Service — check CSS provider status'],
          script: ['sudo /opt/vc/bin/debug.py --tunnelstats | grep -i css', 'sudo /opt/vc/bin/debug.py --flows | grep -i css'],
        },
        {
          cli: ["Run 'debug.py --gateways' after updating CSS configuration to verify the Gateway is re-establishing the CSS tunnel", "Run 'debug.py --flow_stats' to confirm CSS-bound traffic is no longer being dropped or sent direct"],
          gui: ['VCO > Configure > Network > Cloud Security Service — verify CSS provider configuration (Zscaler, Symantec, etc.)', 'VCO > Configure > Business Policy > [Rule] > Action > Network Service: Cloud Security Service', 'VCO > Configure > Edges > [Edge] > Device > Cloud Security — verify Edge-level CSS settings', 'VCO > Configure > Network > Cloud Security Service > [Provider] > Verify API credentials and tunnel endpoints'],
        },
        {
          cli: ["Run 'debug.py --gateways' — CSS tunnel through the Gateway should show 'UP'", "Run 'debug.py --flow_stats' — CSS-bound flows should show traffic being forwarded through the CSS path"],
          gui: ['VCO > Monitor > Edges > [Edge] > Tunnels — CSS tunnel "Up"', 'VCO > Monitor > Edges > [Edge] > Events — no CSS failure events'],
        },
        ['CSS tunnel failures cause traffic to be sent direct (bypassing security) or dropped — check Business Policy fallback action', 'Verify CSS provider API credentials are not expired', 'CSS requires Edge to have a public IP or NAT traversal capability'],
        {
          documentationLinks: [{ title: 'VMware SD-WAN Cloud Security', url: 'https://docs.vmware.com/en/VMware-SD-WAN/index.html' }],
          tacNotes: ['Collect CSS tunnel status and events from VCO', 'Contact CSS provider (Zscaler/Symantec) TAC if tunnel is down on their side'],
        },
      ),
      edge_activation_stuck: fb(
        {
          cli: ["Run 'debug.py --interfaces' on the Edge CLI (if accessible via console) to verify the WAN interface has an IP address and is UP — activation requires outbound HTTPS connectivity", "Run 'debug.py --gateways' to check if the Edge can see any Gateways — if the Edge has partial connectivity it may show Gateway discovery attempts"],
          gui: ['VCO > Configure > Edges > [Edge] — check activation status', 'VCO > Monitor > Edges > [Edge] > Events — check for activation errors', 'VCO > Configure > Edges > [Edge] > Device > Activation — check activation key'],
          script: ['# On Edge appliance (if accessible via console/SSH):', 'sudo /opt/vc/bin/debug.py --status', 'cat /opt/vc/etc/activation.json', 'curl -v https://<vco-hostname>/portal/'],
        },
        {
          cli: ["Run 'debug.py --interfaces' after configuring the WAN interface to confirm it has a valid IP and can reach the internet", "Verify DNS works: run 'nslookup <vco-hostname>' on the Edge CLI — activation fails silently if DNS cannot resolve the VCO"],
          gui: ['VCO > Configure > Edges > [Edge] > Device > Activation > Re-generate Activation Key', 'VCO > Configure > Edges > [Edge] > Device > Activation > Email Activation Link', 'Edge local GUI: https://<edge-ip>/diagnostics.html — enter activation key manually'],
          script: ['# On Edge: Verify DNS resolution of VCO', 'nslookup <vco-hostname>', '# Verify NTP sync', 'date', 'ntpq -p', '# Verify connectivity to VCO', 'curl -v https://<vco-hostname>/portal/', '# Factory reset Edge if stuck (CAUTION: erases all config)', 'sudo /opt/vc/bin/activate.py --reset'],
        },
        {
          cli: ["Run 'debug.py --gateways' — the Edge should now show assigned Gateways with 'UP' status (indicates successful activation and tunnel establishment)"],
          gui: ['VCO > Configure > Edges > [Edge] — status shows "Connected"', 'VCO > Monitor > Edges > [Edge] > Events — activation success event'],
          script: ['sudo /opt/vc/bin/debug.py --status'],
        },
        ['Edge activation requires: (1) DNS resolution of VCO hostname, (2) HTTPS connectivity to VCO on port 443, (3) Correct activation key, (4) NTP sync for certificate validation', 'If Edge is behind a proxy, configure proxy settings in Edge local GUI first', 'Factory reset erases ALL configuration — only use as absolute last resort'],
        {
          documentationLinks: [{ title: 'VeloCloud Edge Activation', url: 'https://docs.vmware.com/en/VMware-SD-WAN/5.4/sdwan-edge-activation.html' }],
          tacNotes: ['Collect activation logs from Edge: /var/log/activation.log', 'Verify VCO is reachable from Edge network', 'Check if firewall is blocking HTTPS to VCO'],
        },
      ),
    },
  },

  // ═══════════════════════════════════════════════════════════════
  // ARUBA SD-WAN (Silver Peak / EdgeConnect) — Hybrid
  // ═══════════════════════════════════════════════════════════════
  'Silver Peak': {
    vendor: 'Aruba EdgeConnect (Silver Peak)',
    vendorKey: 'silverpeak',
    logo: 'A',
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/20',
    primaryInterface: 'hybrid',
    defaultUrl: 'https://<orchestrator-ip>',
    authentication: 'Log in to Aruba Orchestrator web UI. For EdgeConnect CLI: SSH as admin@<appliance-ip>.',
    gettingStarted: {
      primer: 'Aruba SD-WAN (formerly Silver Peak) uses the Orchestrator GUI as the primary management tool, but EdgeConnect appliances also have a useful CLI. The platform excels at WAN optimization (Unity Boost) and tunnel bonding. Key concepts: Business Intent Overlays define traffic policies, Unity Boost provides TCP/data optimization, and tunnel bonding aggregates multiple WAN links.',
      interfaceNote: 'Hybrid platform. Use Orchestrator GUI for monitoring, configuration, and policy changes. Use EdgeConnect CLI for real-time diagnostics. Orchestrator is the single source of truth for all configuration.',
      loginInfo: 'Orchestrator: https://<orchestrator-ip> (admin credentials). EdgeConnect CLI: ssh admin@<appliance-ip>. EdgeConnect GUI: https://<appliance-ip>. HA peer: ssh admin@<ha-peer-ip>.',
      commonMistakes: [
        'Orchestrator configuration changes take up to 5 minutes to propagate to EdgeConnect appliances',
        'Unity Boost (WAN optimization) requires a license — check license status before troubleshooting optimization issues',
        'Tunnel bonding requires matching configuration on both endpoints',
        'Do not confuse "overlay" tunnels (SD-WAN) with "underlay" tunnels (IPsec)',
        'HA failover takes 3-5 seconds — do not trigger manual failover during business hours unless necessary',
        'Business Intent Overlay changes affect ALL traffic matching that overlay — test with non-critical traffic first',
      ],
      quickLinks: [
        { title: 'Aruba EdgeConnect Documentation', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' },
        { title: 'Aruba SD-WAN Support', url: 'https://asp.arubanetworks.com/' },
      ],
    },
    findings: {
      tunnel_flapping: fb(
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Tunnels — check tunnel state history', 'Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — check tunnel alarms', 'Orchestrator > Monitoring > Overlays — check overlay health'],
          cli: ['show tunnel all', 'show tunnel <id> detail', 'show interface wan', 'show bfd', 'show alarm active'],
        },
        {
          gui: ['Orchestrator > Configuration > Tunnels > [Tunnel] > Advanced Settings — adjust keepalive timers', 'Orchestrator > Configuration > Tunnels > Enable UDP hole punching (if behind NAT)', 'Orchestrator > Configuration > Overlays > [Overlay] > MTU — adjust if fragmentation detected'],
          cli: ['tunnel <id> keepalive-interval 10'],
        },
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Tunnels — status "Up" for 5+ minutes', 'Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — no new tunnel alarms'],
          cli: ['show tunnel all', 'show alarm active'],
        },
        ['Tunnel changes may briefly disrupt traffic — schedule during maintenance window', 'If using tunnel bonding, changes affect ALL bonded tunnels'],
        {
          recommendedVersions: ['ECOS 9.3.x (recommended stable)', 'Orchestrator 9.3.x'],
          documentationLinks: [{ title: 'EdgeConnect Admin Guide', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }],
          tacNotes: ['Collect support dump from Orchestrator', 'Include tunnel health metrics for affected tunnels'],
        },
      ),
      packet_loss: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — check loss metrics', 'Orchestrator > Monitoring > Flows — check per-flow loss'], cli: ['show interface wan | include errors|drops', 'show tunnel all | include loss', 'show flows top'] },
        { gui: ['Orchestrator > Configuration > Business Intent Overlays > [Overlay] > FEC: Enable', 'Orchestrator > Configuration > Business Intent Overlays > [Overlay] > Packet Coalescing: Enable'] },
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — loss decreasing'], cli: ['show tunnel all | include loss'] },
        ['Unity Boost WAN optimization can mask packet loss — check raw tunnel stats'],
        { documentationLinks: [{ title: 'EdgeConnect QoS Guide', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }] },
      ),
      tcp_retransmission: fb(
        { gui: ['Orchestrator > Monitoring > Flows — sort by retransmissions', 'Orchestrator > Monitoring > Appliances > [Appliance] > WAN Optimization'], cli: ['show flows top', 'show optimization statistics'] },
        { gui: ['Orchestrator > Configuration > Business Intent Overlays > [Overlay] > WAN Optimization: Enable (requires Boost license)', 'Orchestrator > Configuration > Business Intent Overlays > Path preference — select lower-latency path'] },
        { gui: ['Orchestrator > Monitoring > WAN Optimization — check optimization savings'], cli: ['show optimization statistics'] },
        ['Unity Boost requires a valid license — check Orchestrator > Administration > Licenses'],
        { documentationLinks: [{ title: 'EdgeConnect WAN Optimization', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }] },
      ),
      ddos_syn_flood: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Firewall'], cli: ['show firewall statistics', 'show flows top | include SYN'] },
        { gui: ['Orchestrator > Configuration > Security > Firewall Rules > Add Rule > Block source IP'] },
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Firewall — blocked count increasing'] },
        ['Firewall rules propagate within 5 minutes — do not create duplicate rules'],
        { documentationLinks: [{ title: 'EdgeConnect Security', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }] },
      ),
      c2_beaconing: fb(
        { gui: ['Orchestrator > Monitoring > Flows — filter by destination IP, look for regular intervals'], cli: ['show flows top | include <C2_IP>'] },
        { gui: ['Orchestrator > Configuration > Security > Firewall Rules > Block destination IP <C2_IP>'] },
        { gui: ['Orchestrator > Monitoring > Flows — no new flows to C2 IP'] },
        ['CRITICAL: Isolate the infected host FIRST', 'Preserve all logs for forensic investigation'],
        { documentationLinks: [{ title: 'EdgeConnect Security', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }] },
      ),
      dns_tunneling: fb(
        { gui: ['Orchestrator > Monitoring > Flows — filter by port 53'], cli: ['show flows top | include :53'] },
        { gui: ['Orchestrator > Configuration > Security > Firewall Rules > Block DNS to suspicious domain'] },
        { gui: ['Orchestrator > Monitoring > Flows — DNS traffic to suspicious domain stopped'] },
        ['DNS tunneling indicates active data exfiltration — treat as P1 security incident'],
        { documentationLinks: [{ title: 'EdgeConnect Security', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }] },
      ),
      port_scan: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Firewall — check blocked connections'], cli: ['show firewall statistics', 'show flows top | include <scanner_ip>'] },
        { gui: ['Orchestrator > Configuration > Security > Firewall Rules > Add Rule > Block source IP'] },
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Firewall — scanner blocked'], cli: ['show firewall statistics'] },
        ['Verify the source is not an authorized vulnerability scanner before blocking'],
      ),
      tcp_handshake_failure: fb(
        { gui: ['Orchestrator > Monitoring > Flows — filter by destination IP, check state'], cli: ['show flows top | include <dest_ip>', 'show tunnel all', 'show route'] },
        { gui: ['Orchestrator > Configuration > Business Intent Overlays > [Overlay] > Path preference — select best path'], cli: ['show route <dest_ip>'] },
        { gui: ['Orchestrator > Monitoring > Flows — connections to destination succeeding'], cli: ['show flows top | include <dest_ip>'] },
        ['Check if the destination is reachable through the overlay', 'Verify firewall rules are not blocking the destination port'],
      ),
      arp_conflict: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — check ARP alarms'], cli: ['show arp', 'show interface lan'] },
        { cli: ['clear arp', '! Enable DAI on the LAN switch'], gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — identify conflicting MACs'] },
        { cli: ['show arp | include <conflict_ip>'], gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — no ARP alarms'] },
        ['ARP conflicts are LAN-side — configure DAI on the LAN switch, not EdgeConnect'],
      ),
      voip_quality: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — check jitter/loss', 'Orchestrator > Monitoring > Flows — filter RTP traffic'], cli: ['show flows top | include RTP', 'show optimization statistics'] },
        { gui: ['Orchestrator > Configuration > Business Intent Overlays > [Overlay] > QoS: Voice Priority', 'Orchestrator > Configuration > Business Intent Overlays > [Overlay] > FEC: Enable'], cli: ['show qos statistics'] },
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — jitter <30ms, loss <1%'], cli: ['show qos statistics'] },
        ['Unity Boost WAN optimization can improve voice quality if licensed', 'Ensure voice traffic is classified correctly in Business Intent Overlays'],
        { tacNotes: ['Collect support dump and flow statistics from Orchestrator'] },
      ),
      dhcp_rogue_server: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — check DHCP alarms'], cli: ['show dhcp', 'show flows top | include :67'] },
        { gui: ['Orchestrator > Configuration > Appliances > [Appliance] > DHCP — verify server settings', 'Enable DHCP snooping on the LAN switch'] },
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — no DHCP alarms'], cli: ['show dhcp'] },
        ['DHCP snooping must be configured on the LAN switch, not EdgeConnect'],
      ),
      ntp_amplification: fb(
        { gui: ['Orchestrator > Monitoring > Flows — filter UDP port 123'], cli: ['show flows top | include :123', 'show ntp'] },
        { gui: ['Orchestrator > Configuration > Security > Firewall Rules > Rate-limit NTP', 'Orchestrator > Configuration > Appliances > [Appliance] > NTP — verify server list'] },
        { gui: ['Orchestrator > Monitoring > Flows — NTP traffic normalized'], cli: ['show ntp'] },
        ['Block NTP amplification at the perimeter first'],
      ),
      tcp_zero_window: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — check latency spikes'], cli: ['show interface wan | include drops', 'show flows top'] },
        { gui: ['Orchestrator > Configuration > Business Intent Overlays > [Overlay] > Bandwidth — ensure sufficient allocation', 'Check application server resources'], cli: ['show optimization statistics'] },
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — latency normalized'] },
        ['Zero Window is usually a receiver-side application problem, not EdgeConnect'],
      ),
      tcp_out_of_order: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — check per-path metrics', 'Orchestrator > Monitoring > Flows — check affected flows'], cli: ['show flows top', 'show tunnel all | include loss|reorder'] },
        { gui: ['Orchestrator > Configuration > Business Intent Overlays > [Overlay] > Path preference — use single path for sensitive flows'], cli: ['show tunnel all'] },
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — OOO decreasing'], cli: ['show flows top'] },
        ['Tunnel bonding may cause OOO if paths have different latencies', 'Use single-path steering for latency-sensitive applications'],
      ),
      tls_weakness: fb(
        { gui: ['Orchestrator > Administration > SSL Settings — check minimum TLS version'], cli: ['show ssl', 'openssl s_client -connect <server_ip>:<port> 2>/dev/null | grep -i "protocol\\|cipher"'] },
        { gui: ['Orchestrator > Administration > SSL Settings — set minimum TLS 1.2', 'Contact the server administrator to update TLS configuration'] },
        { gui: ['Orchestrator > Administration > SSL Settings — TLS 1.2+ enforced'] },
        ['TLS weakness is usually on the server side, not EdgeConnect'],
      ),
      hsrp_instability: fb(
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — check gateway alarms'], cli: ['show route', 'show arp | include <gateway_ip>'] },
        { gui: ['Orchestrator > Configuration > Appliances > [Appliance] > WAN — verify gateway IP', 'Configure HSRP/VRRP preempt delay on the LAN routers'] },
        { gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — no gateway alarms'] },
        ['HSRP/VRRP is configured on LAN routers, not EdgeConnect'],
      ),
      high_rtt: fb(
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — check latency per tunnel', 'Orchestrator > Monitoring > Flows — check per-flow latency', 'Orchestrator > Monitoring > Overlays — check overlay latency metrics'],
          cli: ['show tunnel all | include latency', 'show flows top', 'show interface wan | include delay'],
        },
        {
          gui: ['Orchestrator > Configuration > Business Intent Overlays > [Overlay] > Path preference — select lower-latency path', 'Orchestrator > Configuration > Business Intent Overlays > [Overlay] > WAN Optimization: Enable (requires Boost license)'],
          cli: ['show optimization statistics'],
        },
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Health — latency decreasing'],
          cli: ['show tunnel all | include latency'],
        },
        ['Unity Boost TCP optimization can reduce effective latency for TCP traffic', 'Check underlay ISP latency before adjusting SD-WAN settings'],
        { documentationLinks: [{ title: 'EdgeConnect Performance', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }] },
      ),
      unity_boost_failure: fb(
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > WAN Optimization — check optimization status', 'Orchestrator > Monitoring > Appliances > [Appliance] > WAN Optimization > Savings — check compression/dedup ratios', 'Orchestrator > Administration > Licenses — check Boost license status'],
          cli: ['show optimization statistics', 'show optimization connections', 'show license', 'show boost status'],
        },
        {
          gui: ['Orchestrator > Administration > Licenses — verify Boost license is active and not expired', 'Orchestrator > Configuration > Business Intent Overlays > [Overlay] > WAN Optimization: Enable', 'Orchestrator > Configuration > Appliances > [Appliance] > Optimization — verify optimization is enabled per-appliance', 'Orchestrator > Configuration > Business Intent Overlays > [Overlay] > TCP Optimization: Enable'],
          cli: ['! Restart optimization engine', 'restart optimization'],
        },
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > WAN Optimization — savings percentage increasing', 'Orchestrator > Monitoring > Appliances > [Appliance] > WAN Optimization > Connections — optimized connections visible'],
          cli: ['show optimization statistics', 'show optimization connections'],
        },
        ['Unity Boost requires a valid license on BOTH endpoints — optimization only works between two licensed EdgeConnect appliances', 'Boost optimization does NOT work for encrypted traffic (HTTPS/TLS) unless SSL inspection is enabled', 'Restarting the optimization engine briefly interrupts optimized connections', 'Check disk space on EdgeConnect — deduplication requires local storage'],
        {
          documentationLinks: [{ title: 'EdgeConnect WAN Optimization', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }],
          tacNotes: ['Collect optimization statistics from both endpoints', 'Include license status from Orchestrator'],
        },
      ),
      tunnel_bonding_failure: fb(
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Tunnels — check bonded tunnel status', 'Orchestrator > Monitoring > Overlays — check overlay bonding health', 'Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — check bonding alarms'],
          cli: ['show tunnel all', 'show tunnel bonding', 'show interface wan', 'show bfd'],
        },
        {
          gui: ['Orchestrator > Configuration > Tunnels > [Tunnel] > Bonding — verify bonding is enabled on both endpoints', 'Orchestrator > Configuration > Tunnels > [Tunnel] > Advanced — verify MTU matches on both sides', 'Orchestrator > Configuration > Appliances > [Appliance] > WAN — verify WAN labels match tunnel config'],
          cli: ['! Verify bonding config matches on both endpoints', 'show tunnel <id> detail', 'show interface wan'],
        },
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > Tunnels — bonded tunnel "Up" with all members active'],
          cli: ['show tunnel bonding', 'show tunnel all'],
        },
        ['Tunnel bonding requires matching configuration on BOTH endpoints — check both sides', 'Bonded tunnels aggregate bandwidth — if one member goes down, throughput drops proportionally', 'WAN labels must match between tunnel config and WAN interface config', 'MTU mismatch between bonded members causes fragmentation and performance issues'],
        {
          documentationLinks: [{ title: 'EdgeConnect Tunnel Bonding', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }],
          tacNotes: ['Collect tunnel status from both endpoints', 'Include WAN interface config and labels'],
        },
      ),
      bi_policy_mismatch: fb(
        {
          gui: ['Orchestrator > Configuration > Business Intent Overlays — review all overlay policies', 'Orchestrator > Monitoring > Flows — check which overlay each flow is using', 'Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — check for policy mismatch alarms'],
          cli: ['show flows top', 'show policy', 'show overlay'],
        },
        {
          gui: ['Orchestrator > Configuration > Business Intent Overlays > [Overlay] > Match Criteria — verify application/subnet matching', 'Orchestrator > Configuration > Business Intent Overlays > [Overlay] > Breakout — verify local internet breakout settings', 'Orchestrator > Configuration > Business Intent Overlays > [Overlay] > Priority — adjust overlay priority order (higher priority overlays match first)'],
          cli: ['show policy', 'show overlay'],
        },
        {
          gui: ['Orchestrator > Monitoring > Flows — flows using correct overlay', 'Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — no policy mismatch alarms'],
          cli: ['show flows top'],
        },
        ['Business Intent Overlays are evaluated in priority order — a higher-priority overlay may match traffic before the intended one', 'Changes take up to 5 minutes to propagate — wait before re-checking', 'Local internet breakout bypasses the overlay — verify breakout settings if traffic is not going through SD-WAN'],
        {
          documentationLinks: [{ title: 'EdgeConnect Business Intent', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }],
          tacNotes: ['Collect flow table and policy config from Orchestrator'],
        },
      ),
      ha_failover: fb(
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > HA Status — check active/standby state', 'Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — check HA alarms', 'Orchestrator > Monitoring > Appliances > [Appliance] > Events — filter for HA events'],
          cli: ['show ha status', 'show ha peer', 'show interface ha', 'show alarm active'],
        },
        {
          gui: ['Orchestrator > Configuration > Appliances > [Appliance] > High Availability — verify HA config', 'Orchestrator > Configuration > Appliances > [Appliance] > High Availability > HA Interface — verify HA link is connected', 'Orchestrator > Configuration > Appliances > [Appliance] > High Availability > Preemption — configure preemption if needed'],
          cli: ['! Check HA link connectivity', 'show interface ha', '! Force failover (CAUTION)', 'ha failover'],
        },
        {
          gui: ['Orchestrator > Monitoring > Appliances > [Appliance] > HA Status — active/standby roles correct', 'Orchestrator > Monitoring > Appliances > [Appliance] > Alarms — no HA alarms'],
          cli: ['show ha status', 'show ha peer'],
        },
        ['HA failover takes 3-5 seconds and drops all active sessions briefly', 'HA requires a dedicated HA link between the two appliances — verify physical connectivity', 'Both HA peers must run the same ECOS version', 'Manual failover with "ha failover" drops all traffic — only use during maintenance window'],
        {
          documentationLinks: [{ title: 'EdgeConnect HA Guide', url: 'https://www.arubanetworks.com/techdocs/sdwan/docs/edgeconnect/' }],
          tacNotes: ['Collect HA status from both peers', 'Include HA interface statistics and alarm history'],
        },
      ),
    },
  },

  // ═══════════════════════════════════════════════════════════════
  // FORTINET SD-WAN — CLI-primary
  // ═══════════════════════════════════════════════════════════════
  'Fortinet': {
    vendor: 'Fortinet SD-WAN',
    vendorKey: 'fortinet',
    logo: 'F',
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/20',
    primaryInterface: 'cli',
    defaultUrl: 'https://<fortigate-ip>',
    authentication: 'SSH to FortiGate CLI or log in to FortiOS web GUI. FortiManager for centralized management.',
    gettingStarted: {
      primer: 'Fortinet SD-WAN runs on FortiGate firewalls using FortiOS. It combines SD-WAN with NGFW security in a single appliance. The CLI uses "diagnose" commands for troubleshooting and "config" commands for changes. Key concepts: SD-WAN Zones group interfaces, Health Checks monitor path quality, SD-WAN Rules steer traffic, and ADVPN creates dynamic shortcut tunnels between spokes.',
      interfaceNote: 'CLI-primary platform. FortiGate CLI uses "diagnose" for troubleshooting and "get" for status. The FortiOS GUI provides dashboards at Network > SD-WAN. FortiManager provides centralized management for multi-device deployments.',
      loginInfo: 'CLI: ssh admin@<fortigate-ip>. GUI: https://<fortigate-ip> (admin/blank default — change immediately). FortiManager: https://<fortimanager-ip>. FortiAnalyzer: https://<fortianalyzer-ip>.',
      commonMistakes: [
        'FortiOS "diagnose debug" commands can flood the console — always set a timeout: "diagnose debug duration 60"',
        'ADVPN shortcut tunnels require specific IKE version settings — IKEv2 is recommended',
        'SD-WAN zone changes require re-referencing in firewall policies — check policies after zone changes',
        'FortiGate session helpers can interfere with SD-WAN — disable unnecessary helpers',
        'Always run "execute backup full-config" before making SD-WAN changes',
        'ADVPN shortcuts are dynamic and ephemeral — they appear/disappear as needed (this is normal behavior)',
        'SD-WAN rules are evaluated top-to-bottom — order matters, put specific rules before catch-all rules',
      ],
      quickLinks: [
        { title: 'FortiOS SD-WAN Guide', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/sd-wan' },
        { title: 'FortiGate Troubleshooting', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/954635/troubleshooting' },
        { title: 'Fortinet Support Portal', url: 'https://support.fortinet.com/' },
      ],
    },
    findings: {
      tunnel_flapping: fb(
        {
          cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan member', 'diagnose sys sdwan service', 'get router info routing-table all', 'diagnose vpn tunnel list', 'diagnose vpn ike log-filter dst-addr4 <peer_ip>'],
          gui: ['FortiOS > Network > SD-WAN > SD-WAN Zones — check member status', 'FortiOS > Monitor > SD-WAN Monitor — check health check status', 'FortiOS > Monitor > IPsec Monitor — check tunnel status'],
        },
        {
          cli: ['config system sdwan', '  config health-check', '    edit "HQ_HC"', '      set detect-mode passive', '      set interval 500', '      set failtime 5', '    next', '  end', 'end', '! Restart specific VPN tunnel if stuck', 'diagnose vpn tunnel reset <tunnel_name>'],
          gui: ['FortiOS > Network > SD-WAN > SD-WAN Rules > [Rule] > Health Check — adjust interval', 'FortiOS > VPN > IPsec Tunnels > [Tunnel] > Bring Down / Bring Up'],
        },
        {
          cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan member', 'get router info routing-table all'],
          gui: ['FortiOS > Monitor > SD-WAN Monitor — all health checks green', 'FortiOS > Monitor > IPsec Monitor — tunnel status "Up"'],
        },
        ['ADVPN shortcut tunnels are dynamic — they may appear to "flap" when shortcuts are created/torn down (this is normal)', 'Changing health check settings affects ALL SD-WAN rules using that health check', 'VPN tunnel reset drops all sessions through that tunnel'],
        {
          knownBugs: ['FG-IR-23-001 - ADVPN shortcut flapping with IKEv1 on FortiOS 7.2.x'],
          recommendedVersions: ['FortiOS 7.4.x (recommended)', 'FortiOS 7.2.x (LTS)'],
          documentationLinks: [{ title: 'FortiOS SD-WAN Guide', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/sd-wan' }],
          tacNotes: ['Collect "diagnose sys sdwan health-check" output', 'Include VPN tunnel status from both endpoints'],
        },
      ),
      packet_loss: fb(
        { cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan member', 'diagnose netlink interface list', 'fnsysctl ifconfig'], gui: ['FortiOS > Monitor > SD-WAN Monitor — check loss percentage per member'] },
        { cli: ['config system sdwan', '  config service', '    edit 1', '      set packet-loss-weight 10', '    next', '  end', 'end'], gui: ['FortiOS > Network > SD-WAN > SD-WAN Rules > [Rule] > Performance SLA — adjust loss threshold'] },
        { cli: ['diagnose sys sdwan health-check'], gui: ['FortiOS > Monitor > SD-WAN Monitor — loss percentage decreasing'] },
        ['Changing packet-loss-weight affects path selection for all traffic matching the rule'],
        { documentationLinks: [{ title: 'FortiOS SD-WAN Performance SLA', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/sd-wan' }] },
      ),
      tcp_retransmission: fb(
        { cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan service', 'get router info sdwan-route'], gui: ['FortiOS > Monitor > SD-WAN Monitor — check latency and jitter'] },
        { cli: ['config system sdwan', '  config health-check', '    edit "LATENCY_CHECK"', '      config sla', '        edit 1', '          set latency-threshold 100', '          set jitter-threshold 30', '          set packetloss-threshold 1', '        next', '      end', '    next', '  end', 'end'] },
        { cli: ['diagnose sys sdwan health-check', 'get router info sdwan-route'] },
        ['SLA threshold changes trigger immediate path re-evaluation — may cause brief traffic shift'],
        { documentationLinks: [{ title: 'FortiOS Performance SLA', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/sd-wan' }] },
      ),
      ddos_syn_flood: fb(
        { cli: ['diagnose sys session stat', 'diagnose ips anomaly list', 'get system performance status'], gui: ['FortiOS > FortiView > Threats', 'FortiOS > Monitor > Firewall — check session count'] },
        { cli: ['config firewall DoS-policy', '  edit 1', '    set interface <wan-intf>', '    config anomaly', '      edit "tcp_syn_flood"', '        set status enable', '        set threshold 2000', '      next', '    end', '  next', 'end'], gui: ['FortiOS > Policy & Objects > DoS Policy > Add DoS Policy > TCP SYN Flood threshold'] },
        { cli: ['diagnose ips anomaly list', 'diagnose sys session stat'], gui: ['FortiOS > FortiView > Threats — DDoS blocked count increasing'] },
        ['DoS policy thresholds must be tuned to your environment — too low causes false positives'],
        { documentationLinks: [{ title: 'FortiOS DoS Protection', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/dos-protection' }] },
      ),
      c2_beaconing: fb(
        { cli: ['diagnose sys session list | grep <C2_IP>', 'diagnose ips anomaly list'], gui: ['FortiOS > FortiView > Destinations — filter by C2 IP'] },
        { cli: ['config firewall address', '  edit "BLOCK_C2"', '    set subnet <C2_IP>/32', '  next', 'end', 'config firewall policy', '  edit 0', '    set srcintf "any"', '    set dstaddr "BLOCK_C2"', '    set action deny', '  next', 'end'], gui: ['FortiOS > Policy & Objects > Addresses > Create New > Block C2 IP', 'FortiOS > Policy & Objects > Firewall Policy > Add deny rule'] },
        { cli: ['diagnose sys session list | grep <C2_IP>  ! Should return empty'], gui: ['FortiOS > FortiView > Destinations — no new connections to C2 IP'] },
        ['CRITICAL: Isolate the infected host FIRST', 'Preserve all logs for forensic investigation'],
        { documentationLinks: [{ title: 'FortiOS Firewall Policy', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/firewall-policy' }] },
      ),
      dns_tunneling: fb(
        { cli: ['diagnose sys session list | grep ":53"', 'diagnose test application dnsproxy 7'], gui: ['FortiOS > FortiView > DNS — check for suspicious domains'] },
        { cli: ['config webfilter ftgd-local-cat', '  edit 1', '    set desc "Block DNS Tunnel"', '    set url "<suspicious-domain>"', '  next', 'end'], gui: ['FortiOS > Security Profiles > DNS Filter > Block suspicious domain'] },
        { cli: ['diagnose test application dnsproxy 7'], gui: ['FortiOS > FortiView > DNS — suspicious domain blocked'] },
        ['DNS tunneling indicates active data exfiltration — treat as P1 security incident'],
        { documentationLinks: [{ title: 'FortiOS DNS Filter', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/dns-filter' }] },
      ),
      port_scan: fb(
        { cli: ['diagnose ips anomaly list', 'diagnose sys session stat', 'diagnose sys session list | grep <scanner_ip>'], gui: ['FortiOS > FortiView > Threats — filter by source IP', 'FortiOS > Monitor > Firewall — check session count from scanner'] },
        { cli: ['config firewall address', '  edit "BLOCK_SCANNER"', '    set subnet <scanner_ip>/32', '  next', 'end', 'config firewall policy', '  edit 0', '    set srcaddr "BLOCK_SCANNER"', '    set action deny', '  next', 'end'], gui: ['FortiOS > Policy & Objects > Addresses > Create New > Block scanner IP', 'FortiOS > Policy & Objects > Firewall Policy > Add deny rule'] },
        { cli: ['diagnose sys session list | grep <scanner_ip>  ! Should return empty'], gui: ['FortiOS > FortiView > Threats — scanner IP blocked'] },
        ['Verify the source is not an authorized vulnerability scanner before blocking', 'FortiGate IPS can detect and block port scans automatically'],
      ),
      tcp_handshake_failure: fb(
        { cli: ['diagnose sys sdwan service', 'get router info routing-table all | include <dest_ip>', 'diagnose sys session list | grep <dest_ip>', 'diagnose sniffer packet any "host <dest_ip> and tcp[13]==2" 4 10'], gui: ['FortiOS > Monitor > SD-WAN Monitor — check path to destination', 'FortiOS > Monitor > Routing Monitor — verify route exists'] },
        { cli: ['! Verify firewall policy allows the traffic', 'diagnose firewall policy list | grep <dest_ip>', '! Check NAT configuration', 'get system nat'], gui: ['FortiOS > Policy & Objects > Firewall Policy — verify rule allows destination'] },
        { cli: ['diagnose sys session list | grep <dest_ip>', 'execute ping <dest_ip>'], gui: ['FortiOS > Monitor > SD-WAN Monitor — path to destination healthy'] },
        ['Check if a firewall policy is blocking the destination port', 'Session helpers may interfere with certain protocols'],
      ),
      arp_conflict: fb(
        { cli: ['get system arp | grep <conflict_ip>', 'diagnose netlink interface list', 'diagnose ip arp list'], gui: ['FortiOS > Monitor > ARP Table — check for duplicate IPs'] },
        { cli: ['execute clear system arp table', '! Enable DAI on the LAN switch', 'diagnose ip arp delete <conflict_ip>'], gui: ['FortiOS > Monitor > ARP Table — verify after clear'] },
        { cli: ['get system arp | grep <conflict_ip>'], gui: ['FortiOS > Monitor > ARP Table — single MAC per IP'] },
        ['ARP conflicts are LAN-side — configure DAI on the LAN switch, not FortiGate'],
      ),
      voip_quality: fb(
        { cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan service', 'config firewall shaper traffic-shaper', 'get system performance status'], gui: ['FortiOS > Monitor > SD-WAN Monitor — check jitter/loss per member', 'FortiOS > Policy & Objects > Traffic Shapers — check voice shaper'] },
        { cli: ['config firewall shaper traffic-shaper', '  edit "VOICE-PRIORITY"', '    set guaranteed-bandwidth 1000', '    set maximum-bandwidth 5000', '    set priority high', '  next', 'end', '! Apply to voice firewall policy', 'config firewall policy', '  edit <voice_policy_id>', '    set traffic-shaper "VOICE-PRIORITY"', '  next', 'end'], gui: ['FortiOS > Policy & Objects > Traffic Shapers > Create VOICE-PRIORITY', 'FortiOS > Policy & Objects > Firewall Policy > [Voice Policy] > Traffic Shaper: VOICE-PRIORITY'] },
        { cli: ['diagnose sys sdwan health-check', 'diagnose firewall shaper traffic-shaper list'], gui: ['FortiOS > Monitor > SD-WAN Monitor — voice SLA met'] },
        ['Voice traffic should be DSCP EF (46) — verify marking in firewall policy', 'Traffic shaper changes take effect immediately'],
        { tacNotes: ['Collect "diagnose sys sdwan health-check" and traffic shaper statistics'] },
      ),
      dhcp_rogue_server: fb(
        { cli: ['diagnose sys dhcp lease-list', 'get system dhcp server', 'diagnose sniffer packet any "udp port 67 or udp port 68" 4 10'], gui: ['FortiOS > Monitor > DHCP Monitor — check active leases and servers'] },
        { cli: ['! Enable DHCP snooping on the LAN switch', '! Block rogue DHCP server via firewall policy', 'config firewall policy', '  edit 0', '    set srcaddr "ROGUE_DHCP_SERVER"', '    set service "DHCP"', '    set action deny', '  next', 'end'], gui: ['FortiOS > Policy & Objects > Firewall Policy > Block DHCP from rogue server'] },
        { cli: ['diagnose sys dhcp lease-list'], gui: ['FortiOS > Monitor > DHCP Monitor — only authorized server responding'] },
        ['DHCP snooping is configured on the LAN switch, not FortiGate', 'FortiGate can act as DHCP server — verify it is not conflicting'],
      ),
      ntp_amplification: fb(
        { cli: ['diagnose sys ntp status', 'get system ntp', 'diagnose sniffer packet any "udp port 123" 4 10'], gui: ['FortiOS > System > Settings > NTP — check NTP server configuration'] },
        { cli: ['config system ntp', '  set server-mode disable', 'end', '! Rate-limit NTP at the firewall', 'config firewall DoS-policy', '  edit 1', '    config anomaly', '      edit "udp_flood"', '        set threshold 1000', '      next', '    end', '  next', 'end'], gui: ['FortiOS > System > Settings > NTP — disable NTP server mode'] },
        { cli: ['diagnose sys ntp status'], gui: ['FortiOS > System > Settings > NTP — NTP synchronized'] },
        ['Disable NTP server mode on FortiGate if not needed', 'Block NTP amplification at the perimeter first'],
      ),
      tcp_zero_window: fb(
        { cli: ['diagnose sys session stat', 'get system performance status', 'diagnose hardware sysinfo memory'], gui: ['FortiOS > Dashboard > Status — check CPU/memory utilization'] },
        { cli: ['! Check FortiGate resource usage', 'get system performance status', '! If application-side, increase TCP buffers on the server', 'config system global', '  set tcp-halfclose-timer 120', 'end'], gui: ['FortiOS > Dashboard > Status — verify resource utilization is normal'] },
        { cli: ['get system performance status', 'diagnose sys session stat'], gui: ['FortiOS > Dashboard > Status — resources normalized'] },
        ['Zero Window is usually a receiver-side application problem', 'Check the application server for CPU/memory/disk bottlenecks'],
      ),
      tcp_out_of_order: fb(
        { cli: ['diagnose sys sdwan member', 'diagnose sys sdwan service', 'get router info routing-table all', 'diagnose sys session list | grep <flow>'], gui: ['FortiOS > Monitor > SD-WAN Monitor — check ECMP paths', 'FortiOS > Monitor > Routing Monitor — check route table'] },
        { cli: ['! Ensure per-session load balancing', 'config system sdwan', '  set load-balance-mode source-ip-based', 'end'], gui: ['FortiOS > Network > SD-WAN > SD-WAN Settings > Load Balance Mode: Source IP Based'] },
        { cli: ['diagnose sys sdwan member', 'diagnose sys sdwan service'], gui: ['FortiOS > Monitor > SD-WAN Monitor — OOO packets decreasing'] },
        ['Per-packet load balancing causes OOO — use source-IP or session-based', 'ECMP across SD-WAN members may split flows'],
      ),
      tls_weakness: fb(
        { cli: ['diagnose sys session list | grep ssl', 'get vpn ssl settings', 'diagnose vpn ssl list'], gui: ['FortiOS > VPN > SSL-VPN Settings — check TLS version', 'FortiOS > System > Settings > HTTPS — check admin TLS version'] },
        { cli: ['config system global', '  set admin-https-ssl-versions tlsv1-2 tlsv1-3', 'end', 'config vpn ssl settings', '  set ssl-min-proto-ver tls1-2', 'end'], gui: ['FortiOS > System > Settings > HTTPS > SSL Versions: TLS 1.2+', 'FortiOS > VPN > SSL-VPN Settings > Minimum TLS: 1.2'] },
        { cli: ['get vpn ssl settings | grep ssl-min', 'get system global | grep admin-https-ssl'], gui: ['FortiOS > System > Settings — TLS 1.2+ enforced'] },
        ['Changing TLS version may disconnect active SSL-VPN users', 'Ensure all clients support TLS 1.2 before enforcing'],
      ),
      hsrp_instability: fb(
        { cli: ['get router info routing-table all', 'diagnose sys arp list | include <gateway_ip>', 'execute ping <gateway_ip>'], gui: ['FortiOS > Monitor > Routing Monitor — check default gateway'] },
        { cli: ['! Configure gateway health monitoring', 'config system link-monitor', '  edit "GW-MONITOR"', '    set srcintf <lan-intf>', '    set server <gateway_ip>', '    set protocol ping', '    set interval 5', '  next', 'end'], gui: ['FortiOS > Network > Link Health Monitor > Add monitor for gateway'] },
        { cli: ['get router info routing-table all', 'diagnose sys link-monitor status'], gui: ['FortiOS > Monitor > Link Health Monitor — gateway stable'] },
        ['HSRP/VRRP is configured on LAN routers, not FortiGate', 'FortiGate link monitor can detect gateway changes and trigger failover'],
      ),
      high_rtt: fb(
        {
          cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan member', 'diagnose sys sdwan service', 'execute ping-options source <wan-ip>', 'execute ping <remote-ip>'],
          gui: ['FortiOS > Monitor > SD-WAN Monitor — check latency per member', 'FortiOS > Monitor > SD-WAN Monitor > Health Check — check latency trends'],
        },
        {
          cli: ['config system sdwan', '  config health-check', '    edit "LATENCY_HC"', '      config sla', '        edit 1', '          set latency-threshold 100', '        next', '      end', '    next', '  end', '  config service', '    edit 1', '      set sla 1', '      set priority-members 1', '    next', '  end', 'end'],
          gui: ['FortiOS > Network > SD-WAN > SD-WAN Rules > [Rule] > Performance SLA — set latency threshold', 'FortiOS > Network > SD-WAN > SD-WAN Rules > [Rule] > Priority Members — prefer lower-latency member'],
        },
        {
          cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan service'],
          gui: ['FortiOS > Monitor > SD-WAN Monitor — latency within SLA'],
        },
        ['High RTT may be underlay ISP issue — check with traceroute', 'SLA-based routing triggers immediate path switch when threshold is exceeded'],
        { documentationLinks: [{ title: 'FortiOS SD-WAN Performance SLA', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/sd-wan' }] },
      ),
      advpn_shortcut_flapping: fb(
        {
          cli: ['diagnose vpn tunnel list | grep shortcut', 'diagnose vpn ike gateway list', 'diagnose vpn ike log-filter dst-addr4 <peer_ip>', 'diagnose debug application ike -1', 'diagnose debug duration 60', 'diagnose debug enable', 'get vpn ipsec tunnel summary'],
          gui: ['FortiOS > Monitor > IPsec Monitor — check shortcut tunnel status', 'FortiOS > Monitor > SD-WAN Monitor — check ADVPN member status', 'FortiOS > Log & Report > Events > VPN — check for IKE negotiation failures'],
        },
        {
          cli: ['! Verify IKE version is v2 (required for stable ADVPN)', 'config vpn ipsec phase1-interface', '  edit "ADVPN-SHORTCUT"', '    set ike-version 2', '    set auto-discovery-receiver enable', '    set auto-discovery-sender enable', '    set dpd on-idle', '    set dpd-retryinterval 10', '  next', 'end', '! Adjust DPD to prevent premature shortcut teardown', 'config vpn ipsec phase1-interface', '  edit "ADVPN-SHORTCUT"', '    set idle-timeout enable', '    set idle-timeoutinterval 15', '  next', 'end'],
          gui: ['FortiOS > VPN > IPsec Tunnels > [ADVPN Tunnel] > Edit > IKE Version: 2', 'FortiOS > VPN > IPsec Tunnels > [ADVPN Tunnel] > Edit > Dead Peer Detection: On Idle', 'FortiOS > VPN > IPsec Tunnels > [ADVPN Tunnel] > Edit > Auto-Discovery: Enable Sender + Receiver'],
        },
        {
          cli: ['diagnose vpn tunnel list | grep shortcut', 'diagnose vpn ike gateway list', 'get vpn ipsec tunnel summary'],
          gui: ['FortiOS > Monitor > IPsec Monitor — shortcut tunnels stable', 'FortiOS > Log & Report > Events > VPN — no IKE failures'],
        },
        ['ADVPN shortcuts are DYNAMIC — they are created on-demand and torn down after idle timeout. Brief "flapping" during creation/teardown is NORMAL', 'IKEv1 causes significantly more shortcut instability than IKEv2 — always use IKEv2', 'DPD settings affect how quickly dead shortcuts are detected — too aggressive causes false teardowns', 'Shortcut tunnels bypass the hub — ensure firewall policies allow spoke-to-spoke traffic'],
        {
          knownBugs: ['FG-IR-23-001 - ADVPN shortcut flapping with IKEv1 on FortiOS 7.2.x', 'FG-IR-23-045 - Shortcut tunnel MTU issue on FortiOS 7.2.3'],
          recommendedVersions: ['FortiOS 7.4.x (recommended for ADVPN)', 'FortiOS 7.2.7+ (if staying on 7.2 branch)'],
          documentationLinks: [
            { title: 'FortiOS ADVPN Guide', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/advpn' },
            { title: 'ADVPN Troubleshooting', url: 'https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-ADVPN-shortcut-tunnels/ta-p/195870' },
          ],
          tacNotes: ['Collect "diagnose vpn tunnel list" and "diagnose vpn ike gateway list" from hub and both spokes', 'Include IKE debug logs: "diagnose debug app ike -1" (set duration 60 first)'],
        },
      ),
      sdwan_zone_misconfiguration: fb(
        {
          cli: ['config system sdwan', '  show', 'end', 'diagnose sys sdwan member', 'diagnose sys sdwan service', 'diagnose firewall proute list', 'get router info routing-table all'],
          gui: ['FortiOS > Network > SD-WAN > SD-WAN Zones — check zone membership', 'FortiOS > Network > SD-WAN > SD-WAN Rules — check rule-to-zone mapping', 'FortiOS > Policy & Objects > Firewall Policy — check policies reference correct zones'],
        },
        {
          cli: ['! Verify all SD-WAN members are in correct zones', 'config system sdwan', '  config zone', '    edit "virtual-wan-link"', '    next', '    edit "UNDERLAY"', '    next', '    edit "OVERLAY"', '    next', '  end', '  config members', '    edit 1', '      set interface "wan1"', '      set zone "UNDERLAY"', '    next', '    edit 2', '      set interface "ADVPN"', '      set zone "OVERLAY"', '    next', '  end', 'end', '! IMPORTANT: Update firewall policies to reference new zones', 'config firewall policy', '  edit <policy_id>', '    set srcintf "OVERLAY"', '    set dstintf "lan"', '  next', 'end'],
          gui: ['FortiOS > Network > SD-WAN > SD-WAN Zones > Add/Edit zone membership', 'FortiOS > Policy & Objects > Firewall Policy — update source/destination interfaces to use SD-WAN zones'],
        },
        {
          cli: ['diagnose sys sdwan member', 'diagnose sys sdwan service', 'diagnose firewall proute list'],
          gui: ['FortiOS > Network > SD-WAN > SD-WAN Zones — all members in correct zones', 'FortiOS > Monitor > SD-WAN Monitor — traffic flowing through expected zones'],
        },
        ['SD-WAN zone changes REQUIRE updating firewall policies — traffic will be blocked if policies still reference old interface names', 'SD-WAN rules reference zones, not individual interfaces — ensure rules match the correct zone', 'Changing zone membership may briefly disrupt traffic through that member', 'Always backup config before zone changes: "execute backup full-config"'],
        {
          documentationLinks: [{ title: 'FortiOS SD-WAN Zones', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/sd-wan-zones' }],
          tacNotes: ['Collect full SD-WAN config: "config system sdwan" > "show"', 'Include firewall policy list: "show firewall policy"'],
        },
      ),
      session_helper_conflict: fb(
        {
          cli: ['diagnose sys session-helper list', 'diagnose sys session stat', 'diagnose sys session list | grep <affected_port>', 'get system session-helper'],
          gui: ['FortiOS > System > Settings > Session Helpers — check active helpers', 'FortiOS > Monitor > Firewall — check for unexpected session behavior'],
        },
        {
          cli: ['! Disable problematic session helper', 'config system session-helper', '  delete <helper_id>', 'end', '! Common helpers that conflict with SD-WAN:', '! SIP helper (port 5060) — interferes with VoIP over SD-WAN', '! TFTP helper (port 69) — interferes with TFTP over tunnels', '! H323 helper (port 1720) — interferes with video conferencing', '! To disable SIP ALG specifically:', 'config system settings', '  set sip-helper disable', '  set sip-nat-trace disable', 'end'],
          gui: ['FortiOS > System > Settings > Session Helpers > Delete problematic helper', 'FortiOS > System > Settings > SIP > Disable SIP Helper'],
        },
        {
          cli: ['diagnose sys session-helper list', 'diagnose sys session list | grep <affected_port>'],
          gui: ['FortiOS > System > Settings > Session Helpers — problematic helper removed'],
        },
        ['Session helpers (ALGs) modify packet payloads — they can break applications that traverse SD-WAN tunnels', 'SIP ALG is the most common offender — disable it if VoIP has issues over SD-WAN', 'Disabling a session helper may require clearing existing sessions: "diagnose sys session clear"', 'Some helpers are required for specific protocols — only disable the ones causing issues'],
        {
          documentationLinks: [{ title: 'FortiOS Session Helpers', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/session-helpers' }],
          tacNotes: ['Collect session helper list and affected session details'],
        },
      ),
      performance_sla_violation: fb(
        {
          cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan service', 'diagnose sys sdwan member', 'get router info sdwan-route'],
          gui: ['FortiOS > Monitor > SD-WAN Monitor — check health check status (green/red)', 'FortiOS > Monitor > SD-WAN Monitor > Health Check — check SLA violation history', 'FortiOS > Network > SD-WAN > SD-WAN Rules — check which rules reference the violated SLA'],
        },
        {
          cli: ['config system sdwan', '  config health-check', '    edit "SLA-CHECK"', '      set server "8.8.8.8"', '      set protocol ping', '      set interval 500', '      set failtime 5', '      set recoverytime 5', '      config sla', '        edit 1', '          set latency-threshold 150', '          set jitter-threshold 50', '          set packetloss-threshold 2', '        next', '      end', '    next', '  end', 'end'],
          gui: ['FortiOS > Network > SD-WAN > Performance SLA > [SLA] — adjust thresholds', 'FortiOS > Network > SD-WAN > SD-WAN Rules > [Rule] > Performance SLA — adjust or change SLA reference'],
        },
        {
          cli: ['diagnose sys sdwan health-check', 'diagnose sys sdwan service', 'get router info sdwan-route'],
          gui: ['FortiOS > Monitor > SD-WAN Monitor — all health checks green'],
        },
        ['SLA violations trigger immediate path failover — this is by design', 'If ALL members violate SLA, traffic uses the "best effort" member (least bad)', 'Health check interval affects detection speed — lower interval = faster detection but more overhead', 'SLA thresholds that are too tight cause unnecessary path flapping'],
        {
          documentationLinks: [{ title: 'FortiOS Performance SLA', url: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/584396/performance-sla' }],
          tacNotes: ['Collect "diagnose sys sdwan health-check" output over 5-minute interval', 'Include SD-WAN service and member status'],
        },
      ),
    },
  },

  // ═══════════════════════════════════════════════════════════════
  // JUNIPER SD-WAN (Session Smart / Mist) — Hybrid
  // ═══════════════════════════════════════════════════════════════
  'Juniper': {
    vendor: 'Juniper SD-WAN (Session Smart / Mist)',
    vendorKey: 'juniper',
    logo: 'J',
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-500/10',
    borderColor: 'border-cyan-500/20',
    primaryInterface: 'hybrid',
    defaultUrl: 'https://manage.mist.com',
    authentication: 'Log in to Mist Cloud portal or SSH to Session Smart Router (SSR) CLI.',
    gettingStarted: {
      primer: 'Juniper SD-WAN uses Session Smart Routers (SSR, formerly 128T) managed via Mist Cloud or Conductor. SSR uses session-based routing (no tunnels) which is unique among SD-WAN vendors. Mist provides AI-driven insights and anomaly detection. Key concepts: Services define what traffic to route, Service Routes define where to send it, and Tenants define who can access services. There are NO tunnels — SSR uses SVR (Secure Vector Routing) which adds metadata to existing packets.',
      interfaceNote: 'Hybrid platform. Use Mist Cloud GUI for monitoring, AI insights, and WAN Assurance anomaly detection. Use SSR CLI for detailed session and routing diagnostics. Conductor provides centralized configuration management.',
      loginInfo: 'Mist Cloud: https://manage.mist.com (SSO credentials). SSR CLI: ssh admin@<ssr-ip>. Conductor: https://<conductor-ip>. SRX (if integrated): ssh admin@<srx-ip>.',
      commonMistakes: [
        'SSR does NOT use tunnels — it uses session-based routing (SVR). Do not look for "tunnel status"',
        'Mist WAN Assurance anomalies are AI-detected — they may need human validation before acting',
        'SSR configuration changes via Conductor take 1-2 minutes to propagate',
        'The "show sessions" command can produce very large output — always use filters like "by-service" or "| grep"',
        'SSR service-routes are directional — you need routes on BOTH routers for bidirectional traffic',
        'Mist Cloud requires internet connectivity — SSR continues forwarding if Mist is unreachable, but monitoring stops',
      ],
      quickLinks: [
        { title: 'Juniper SSR Documentation', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' },
        { title: 'Mist WAN Assurance', url: 'https://www.juniper.net/us/en/products/cloud-services/wan-assurance.html' },
        { title: 'Juniper Support', url: 'https://support.juniper.net/' },
      ],
    },
    findings: {
      tunnel_flapping: fb(
        {
          cli: ['show peers', 'show service-path', 'show sessions', 'show bfd', 'show alarms', 'show network-interface'],
          gui: ['Mist > WAN > Edges > [Edge] > Insights — check path health', 'Mist > WAN > Edges > [Edge] > Events — check for peer down events', 'Conductor > Routers > [Router] > Peers — check peer status'],
        },
        {
          cli: ['config authority router <name>', '  bfd desired-tx-interval 1000', '  bfd required-min-rx-interval 1000', '  bfd multiplier 5', 'exit', 'commit'],
          gui: ['Conductor > Configuration > Router > [Router] > BFD Settings — adjust timers', 'Mist > WAN > Site > [Site] > WAN Edge Template — adjust path settings'],
        },
        {
          cli: ['show peers', 'show bfd', 'show alarms'],
          gui: ['Mist > WAN > Edges > [Edge] > Insights — peer status stable', 'Conductor > Routers > [Router] > Peers — all peers "Up"'],
        },
        ['SSR uses session-based routing, not tunnels — "flapping" means peer connectivity issues', 'BFD timer changes require commit and affect all peers on the interface'],
        {
          recommendedVersions: ['SSR 6.1.x (recommended)', 'Conductor 6.1.x'],
          documentationLinks: [{ title: 'Juniper SSR Documentation', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }],
          tacNotes: ['Collect "request support information" from both routers', 'Include session and peer status'],
        },
      ),
      packet_loss: fb(
        { cli: ['show service-path', 'show sessions by-service', 'show stats packet-processing action'], gui: ['Mist > WAN > Edges > [Edge] > Insights — check loss metrics', 'Mist > WAN > Edges > [Edge] > Applications — check per-app loss'] },
        { cli: ['config authority router <name>', '  service-route <route> service-policy <policy>', '  service-policy <policy> best-effort true', 'exit', 'commit'], gui: ['Mist > WAN > Site > [Site] > Application Policy — adjust path preference'] },
        { cli: ['show service-path', 'show stats packet-processing action'], gui: ['Mist > WAN > Edges > [Edge] > Insights — loss decreasing'] },
        ['SSR path selection is per-session — changes affect new sessions only, not existing ones'],
        { documentationLinks: [{ title: 'SSR Service Routing', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }] },
      ),
      tcp_retransmission: fb(
        { cli: ['show sessions by-service', 'show service-path'], gui: ['Mist > WAN > Edges > [Edge] > Applications — check latency'] },
        { cli: ['config authority service-policy <policy>', '  service-class latency-sensitive', 'exit', 'commit'], gui: ['Mist > WAN > Application Policy — set latency-sensitive class'] },
        { cli: ['show sessions by-service', 'show service-path'], gui: ['Mist > WAN > Edges > [Edge] > Applications — latency improving'] },
        ['Service policy changes affect new sessions only'],
        { documentationLinks: [{ title: 'SSR Service Policy', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }] },
      ),
      ddos_syn_flood: fb(
        { cli: ['show stats packet-processing action failure', 'show sessions'], gui: ['Mist > WAN > Edges > [Edge] > Events — check for anomalies'] },
        { cli: ['config authority access-policy <name>', '  deny source <attacker_ip>/32', 'exit', 'commit'], gui: ['Conductor > Configuration > Access Policies > Add deny rule for attacker IP'] },
        { cli: ['show stats packet-processing action failure'], gui: ['Mist > WAN > Edges > [Edge] > Events — attack traffic blocked'] },
        ['SSR access policies are per-service — ensure the deny rule is applied to the correct service'],
        { documentationLinks: [{ title: 'SSR Access Policies', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }] },
      ),
      c2_beaconing: fb(
        { cli: ['show sessions | grep <C2_IP>'], gui: ['Mist > WAN > Edges > [Edge] > Applications — look for regular interval connections'] },
        { cli: ['config authority access-policy BLOCK-C2', '  deny destination <C2_IP>/32', 'exit', 'commit'], gui: ['Conductor > Configuration > Access Policies > Block C2 destination'] },
        { cli: ['show sessions | grep <C2_IP>  ! Should return empty'] },
        ['CRITICAL: Isolate the infected host FIRST', 'Preserve all logs for forensic investigation'],
        { documentationLinks: [{ title: 'SSR Security', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }] },
      ),
      dns_tunneling: fb(
        { cli: ['show sessions | grep ":53"'], gui: ['Mist > WAN > Edges > [Edge] > Applications — filter DNS'] },
        { cli: ['config authority access-policy BLOCK-DNS-TUNNEL', '  deny destination <suspicious-domain>', 'exit', 'commit'] },
        { cli: ['show sessions | grep ":53"'] },
        ['DNS tunneling indicates active data exfiltration — treat as P1 security incident'],
        { documentationLinks: [{ title: 'SSR DNS Configuration', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }] },
      ),
      port_scan: fb(
        { cli: ['show sessions | grep <scanner_ip>', 'show stats packet-processing action failure'], gui: ['Mist > WAN > Edges > [Edge] > Events — check for anomalies', 'Mist > WAN > Edges > [Edge] > Applications — filter by source IP'] },
        { cli: ['config authority access-policy BLOCK-SCANNER', '  deny source <scanner_ip>/32', 'exit', 'commit'], gui: ['Conductor > Configuration > Access Policies > Add deny rule for scanner IP'] },
        { cli: ['show sessions | grep <scanner_ip>  ! Should return empty'], gui: ['Mist > WAN > Edges > [Edge] > Events — scanner blocked'] },
        ['Verify the source is not an authorized vulnerability scanner before blocking', 'SSR access policies are per-service — ensure deny rule covers all services'],
      ),
      tcp_handshake_failure: fb(
        { cli: ['show service-path', 'show sessions by-service', 'show peers', 'show network-interface'], gui: ['Mist > WAN > Edges > [Edge] > Insights — check path to destination', 'Mist > WAN > Edges > [Edge] > Applications — filter by destination'] },
        { cli: ['! Verify service route exists for the destination', 'show service-path <dest_ip>', '! Check if access policy is blocking', 'show config running authority access-policy'], gui: ['Conductor > Configuration > Services > Verify service route to destination'] },
        { cli: ['show service-path <dest_ip>', 'show sessions by-service'], gui: ['Mist > WAN > Edges > [Edge] > Insights — path to destination healthy'] },
        ['SSR uses session-based routing — verify a service route exists for the destination', 'Access policies may block traffic before it reaches the service route'],
      ),
      arp_conflict: fb(
        { cli: ['show arp', 'show network-interface'], gui: ['Mist > WAN > Edges > [Edge] > Events — check for ARP events'] },
        { cli: ['clear arp', '! Enable DAI on the LAN switch'] },
        { cli: ['show arp | grep <conflict_ip>'], gui: ['Mist > WAN > Edges > [Edge] > Events — no ARP conflict events'] },
        ['ARP conflicts are LAN-side — configure DAI on the LAN switch, not SSR'],
      ),
      voip_quality: fb(
        { cli: ['show sessions by-service | grep voice', 'show service-path', 'show stats packet-processing action'], gui: ['Mist > WAN > Edges > [Edge] > Insights — check jitter/loss', 'Mist > WAN > Edges > [Edge] > Applications — filter voice/RTP'] },
        { cli: ['config authority service-policy VOICE-PRIORITY', '  service-class real-time', '  priority 0', 'exit', 'commit'], gui: ['Mist > WAN > Application Policy > Set voice apps to Real-Time class'] },
        { cli: ['show sessions by-service | grep voice', 'show service-path'], gui: ['Mist > WAN > Edges > [Edge] > Insights — voice quality improved'] },
        ['SSR service-class real-time gives highest priority', 'Service policy changes affect new sessions only'],
        { tacNotes: ['Collect "request support information" and session statistics'] },
      ),
      dhcp_rogue_server: fb(
        { cli: ['show dhcp', 'show sessions | grep ":67\\|:68"'], gui: ['Mist > WAN > Edges > [Edge] > Events — check DHCP events'] },
        { cli: ['! Enable DHCP snooping on the LAN switch', '! SSR can act as DHCP server — verify config', 'show config running authority router <name> dhcp-server'] },
        { cli: ['show dhcp'], gui: ['Mist > WAN > Edges > [Edge] > Events — no rogue DHCP'] },
        ['DHCP snooping is configured on the LAN switch, not SSR'],
      ),
      ntp_amplification: fb(
        { cli: ['show ntp', 'show sessions | grep ":123"'], gui: ['Mist > WAN > Edges > [Edge] > Events — check for NTP anomalies'] },
        { cli: ['config authority access-policy LIMIT-NTP', '  deny source any destination any port 123', 'exit', 'commit'], gui: ['Conductor > Configuration > Access Policies > Rate-limit NTP'] },
        { cli: ['show ntp', 'show sessions | grep ":123"'] },
        ['Block NTP amplification at the perimeter first'],
      ),
      tcp_zero_window: fb(
        { cli: ['show stats packet-processing action', 'show system'], gui: ['Mist > WAN > Edges > [Edge] > Insights — check latency'] },
        { cli: ['! Zero Window is receiver-side — check application server', 'show system  ! Check SSR resource usage'] },
        { cli: ['show stats packet-processing action'], gui: ['Mist > WAN > Edges > [Edge] > Insights — latency normalized'] },
        ['Zero Window is usually a receiver-side application problem, not SSR'],
      ),
      tcp_out_of_order: fb(
        { cli: ['show service-path', 'show peers', 'show sessions by-service'], gui: ['Mist > WAN > Edges > [Edge] > Insights — check path metrics'] },
        { cli: ['! SSR uses per-session routing by default — verify', 'show config running authority router <name> service-route'], gui: ['Mist > WAN > Application Policy — verify per-session path selection'] },
        { cli: ['show service-path', 'show sessions by-service'], gui: ['Mist > WAN > Edges > [Edge] > Insights — OOO decreasing'] },
        ['SSR per-session routing should prevent OOO — check if multiple service-routes exist for same service'],
      ),
      tls_weakness: fb(
        { cli: ['show config running authority web-server', 'show system'], gui: ['Conductor > Configuration > Authority > Web Server — check TLS settings'] },
        { cli: ['config authority web-server', '  tls-version 1.2', 'exit', 'commit'], gui: ['Conductor > Configuration > Authority > Web Server > TLS Version: 1.2'] },
        { cli: ['show config running authority web-server'], gui: ['Conductor > Configuration > Authority > Web Server — TLS 1.2+'] },
        ['Changing TLS version may temporarily disconnect management sessions'],
      ),
      hsrp_instability: fb(
        { cli: ['show arp | grep <gateway_ip>', 'show network-interface', 'show alarms'], gui: ['Mist > WAN > Edges > [Edge] > Events — check for gateway changes'] },
        { cli: ['! Configure gateway monitoring', 'config authority router <name>', '  service-route <route> next-hop <gateway_ip>', 'exit', 'commit'], gui: ['Conductor > Configuration > Router > Service Routes — verify gateway'] },
        { cli: ['show alarms', 'show arp | grep <gateway_ip>'], gui: ['Mist > WAN > Edges > [Edge] > Events — gateway stable'] },
        ['HSRP/VRRP is configured on LAN routers, not SSR', 'SSR will detect gateway changes via ARP'],
      ),
      high_rtt: fb(
        {
          cli: ['show service-path', 'show sessions by-service', 'show peers detail', 'show stats packet-processing action'],
          gui: ['Mist > WAN > Edges > [Edge] > Insights — check latency per path', 'Mist > WAN > Edges > [Edge] > Applications — check per-app latency', 'Mist > WAN > Sites > [Site] > WAN Health — check overall WAN latency'],
        },
        {
          cli: ['config authority service-policy LATENCY-SENSITIVE', '  service-class latency-sensitive', '  path-quality-filter true', '  max-latency 100', 'exit', 'commit'],
          gui: ['Mist > WAN > Application Policy — set latency-sensitive service class', 'Conductor > Configuration > Service Policies > Add LATENCY-SENSITIVE policy'],
        },
        {
          cli: ['show service-path', 'show sessions by-service'],
          gui: ['Mist > WAN > Edges > [Edge] > Insights — latency decreasing'],
        },
        ['SSR path-quality-filter automatically avoids high-latency paths', 'Service policy changes affect new sessions only — existing sessions continue on current path'],
        { documentationLinks: [{ title: 'SSR Service Policy', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }] },
      ),
      ssr_path_selection: fb(
        {
          cli: ['show service-path', 'show service-path detail', 'show sessions by-service', 'show peers', 'show bfd', 'show stats packet-processing action', 'show config running authority service <service-name>'],
          gui: ['Mist > WAN > Edges > [Edge] > Insights — check path selection decisions', 'Mist > WAN > Edges > [Edge] > Applications — check which path each application uses', 'Conductor > Routers > [Router] > Service Paths — check available paths'],
        },
        {
          cli: ['! Verify service-route exists for the destination', 'show config running authority router <name> service-route', '! Adjust service-policy for path selection', 'config authority service-policy <policy>', '  service-class <class>', '  path-quality-filter true', '  max-latency 100', '  max-loss 1', '  max-jitter 30', 'exit', '! Apply policy to service', 'config authority service <service-name>', '  service-policy <policy>', 'exit', 'commit'],
          gui: ['Conductor > Configuration > Services > [Service] > Service Policy — adjust path selection criteria', 'Mist > WAN > Application Policy > [Policy] — adjust path preference'],
        },
        {
          cli: ['show service-path', 'show sessions by-service'],
          gui: ['Mist > WAN > Edges > [Edge] > Insights — traffic using expected paths'],
        },
        ['SSR uses per-SESSION routing, not per-packet — each session is pinned to a path for its lifetime', 'Service-routes must exist on BOTH routers for bidirectional traffic', 'Path quality filter requires BFD to be enabled between peers', 'If no service-route matches, traffic is dropped — always have a catch-all service'],
        {
          documentationLinks: [{ title: 'SSR Service Routing', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }],
          tacNotes: ['Collect "show service-path" and "show sessions by-service" from both routers', 'Include service and service-route configuration'],
        },
      ),
      mist_wan_assurance_anomaly: fb(
        {
          gui: ['Mist > WAN > Edges > [Edge] > Insights — check AI-detected anomalies', 'Mist > WAN > Edges > [Edge] > Events — check for anomaly events', 'Mist > WAN > Sites > [Site] > WAN Health — check site-level anomalies', 'Mist > WAN > Marvis Actions — check AI-recommended actions'],
          cli: ['show alarms', 'show peers', 'show service-path', 'show sessions by-service'],
        },
        {
          gui: ['Mist > WAN > Marvis Actions — review and apply AI-recommended fixes', 'Mist > WAN > Edges > [Edge] > Insights > [Anomaly] — click for recommended action', 'Mist > WAN > Application Policy — adjust policies based on anomaly recommendations'],
          cli: ['! Apply fixes based on Mist recommendations', '! Common: adjust BFD timers, service-policy thresholds, or peer configuration'],
        },
        {
          gui: ['Mist > WAN > Edges > [Edge] > Insights — anomaly resolved', 'Mist > WAN > Marvis Actions — no pending actions'],
          cli: ['show alarms  ! No active alarms'],
        },
        ['Mist WAN Assurance anomalies are AI-detected — they may be false positives, always validate before acting', 'Marvis Actions provides AI-recommended fixes — review carefully before applying', 'Mist requires internet connectivity for anomaly detection — local SSR continues forwarding if Mist is unreachable', 'Historical anomaly data is available in Mist for trend analysis'],
        {
          documentationLinks: [
            { title: 'Mist WAN Assurance', url: 'https://www.juniper.net/us/en/products/cloud-services/wan-assurance.html' },
            { title: 'Marvis Actions', url: 'https://www.juniper.net/us/en/products/cloud-services/marvis-virtual-network-assistant.html' },
          ],
          tacNotes: ['Export anomaly details from Mist dashboard', 'Include SSR alarm and session data for correlation'],
        },
      ),
      service_routing_issue: fb(
        {
          cli: ['show service-path', 'show config running authority service', 'show config running authority router <name> service-route', 'show sessions by-service', 'show peers', 'show network-interface'],
          gui: ['Conductor > Configuration > Services — check service definitions', 'Conductor > Configuration > Router > [Router] > Service Routes — check route existence', 'Mist > WAN > Edges > [Edge] > Applications — check if traffic is being routed'],
        },
        {
          cli: ['! Verify service exists for the destination', 'config authority service <name>', '  address <dest_subnet>', '  access-policy <tenant> allow', '  service-policy <policy>', 'exit', '! Verify service-route exists on this router', 'config authority router <name>', '  service-route <route-name>', '    service-name <service-name>', '    next-hop <peer-router> <network-interface>', '  exit', 'exit', 'commit'],
          gui: ['Conductor > Configuration > Services > Add/Edit service for destination', 'Conductor > Configuration > Router > [Router] > Service Routes > Add route for service'],
        },
        {
          cli: ['show service-path  ! Should show path for the service', 'show sessions by-service  ! Should show active sessions'],
          gui: ['Mist > WAN > Edges > [Edge] > Applications — traffic flowing to destination'],
        },
        ['SSR requires BOTH a service definition AND a service-route for traffic to flow', 'Services define WHAT to route (destination, tenant access), service-routes define WHERE to send it', 'Access policies on services control which tenants can use the service — verify tenant assignment', 'Service-routes are directional — you need routes on BOTH routers for return traffic'],
        {
          documentationLinks: [{ title: 'SSR Service Configuration', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }],
          tacNotes: ['Collect full service and service-route configuration from Conductor', 'Include "show service-path" output from both routers'],
        },
      ),
      srx_sdwan_integration: fb(
        {
          cli: ['! On SRX:', 'show security flow session', 'show security policies hit-count', 'show route', '! On SSR:', 'show peers', 'show service-path', 'show sessions by-service | grep <srx_ip>'],
          gui: ['Mist > WAN > Edges > [Edge] > Insights — check SRX integration status', 'Conductor > Routers > [Router] > Peers — check SRX peer status'],
        },
        {
          cli: ['! Verify SRX is configured as a peer in SSR', 'show config running authority router <name> peer', '! Verify SRX security policies allow SSR traffic', '! On SRX:', 'show security policies | grep <ssr_zone>', '! Verify routing between SRX and SSR', 'show route <ssr_ip>'],
          gui: ['Conductor > Configuration > Router > [Router] > Peers — verify SRX peer configuration', 'Mist > WAN > Edges > [Edge] > Insights — check SRX connectivity'],
        },
        {
          cli: ['show peers  ! SRX peer should show "Up"', 'show service-path  ! Paths through SRX should be available'],
          gui: ['Mist > WAN > Edges > [Edge] > Insights — SRX integration healthy'],
        },
        ['SRX and SSR use different routing paradigms — SRX uses zone-based routing, SSR uses service-based routing', 'Ensure SRX security policies allow traffic from SSR zones', 'SRX SD-WAN integration requires proper BGP or static routing between the two platforms'],
        {
          documentationLinks: [{ title: 'Juniper SD-WAN with SRX', url: 'https://www.juniper.net/documentation/us/en/software/session-smart-router/' }],
          tacNotes: ['Collect peer status from SSR and security policy hit counts from SRX'],
        },
      ),
    },
  },

  // ═══════════════════════════════════════════════════════════════
  // PALO ALTO SD-WAN (Prisma SD-WAN / CloudGenix) — GUI-primary
  // ═══════════════════════════════════════════════════════════════
  'Palo Alto': {
    vendor: 'Palo Alto Prisma SD-WAN (CloudGenix)',
    vendorKey: 'paloalto',
    logo: 'P',
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/20',
    primaryInterface: 'gui',
    defaultUrl: 'https://sdwan.pan.dev',
    authentication: 'Log in to Prisma SD-WAN portal. For ION appliance CLI: SSH as admin@<ion-ip>.',
    gettingStarted: {
      primer: 'Palo Alto Prisma SD-WAN (formerly CloudGenix) is a GUI-first, cloud-managed SD-WAN platform. ION appliances are managed through the Prisma SD-WAN portal. The platform integrates with Prisma Access for SASE. CLI access to ION appliances is limited. Key concepts: Application Definitions classify traffic, Path Selection policies steer traffic, and Prisma Access provides cloud-delivered security.',
      interfaceNote: 'GUI-primary platform. Use Prisma SD-WAN portal for all monitoring and configuration. ION appliance CLI is limited to basic diagnostics. API available via https://api.sase.paloaltonetworks.com for automation.',
      loginInfo: 'Prisma SD-WAN: https://sdwan.pan.dev (SSO credentials). ION CLI: ssh admin@<ion-ip> (limited commands). Prisma Access: https://sase.paloaltonetworks.com. API: https://api.sase.paloaltonetworks.com.',
      commonMistakes: [
        'Prisma SD-WAN uses "Application Definitions" not traditional ACLs — learn the app-based model first',
        'ION appliance CLI is very limited compared to other vendors — most troubleshooting is GUI-based',
        'Policy changes in Prisma SD-WAN portal take 2-5 minutes to push to ION appliances',
        'Prisma Access integration requires separate licensing — verify before troubleshooting SASE issues',
        'Application QoS uses "Application Definitions" — ensure the app is correctly classified before adjusting QoS',
        'Link quality monitoring uses active probes — probe failures may indicate ISP issues, not SD-WAN issues',
      ],
      quickLinks: [
        { title: 'Prisma SD-WAN Documentation', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' },
        { title: 'Prisma SD-WAN API', url: 'https://pan.dev/sdwan/' },
        { title: 'Palo Alto Support', url: 'https://support.paloaltonetworks.com/' },
      ],
    },
    findings: {
      tunnel_flapping: fb(
        {
          gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — check link status', 'Prisma SD-WAN > Monitor > Sites > [Site] > Tunnels — check VPN tunnel status', 'Prisma SD-WAN > Monitor > Sites > [Site] > Events — check for tunnel events', 'Prisma SD-WAN > Monitor > Alerts — check for site-level alerts'],
          cli: ['show vpn status', 'show interface status'],
        },
        {
          gui: ['Prisma SD-WAN > Configure > Sites > [Site] > WAN Interfaces > [Link] — adjust settings', 'Prisma SD-WAN > Configure > Network > VPN > [VPN Profile] — adjust keepalive timers', 'Prisma SD-WAN > Configure > Sites > [Site] > Path Selection — adjust path preference'],
        },
        {
          gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Tunnels — status "Up" for 5+ minutes', 'Prisma SD-WAN > Monitor > Sites > [Site] > Events — no new tunnel events'],
        },
        ['ION appliance restart drops all sessions — only restart as last resort', 'VPN profile changes affect all sites using that profile'],
        {
          recommendedVersions: ['ION 6.2.x (recommended)', 'Controller 6.2.x'],
          documentationLinks: [{ title: 'Prisma SD-WAN Admin Guide', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }],
          tacNotes: ['Collect diagnostic bundle from Prisma SD-WAN portal', 'Include site events and tunnel metrics'],
        },
      ),
      packet_loss: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — check loss percentage', 'Prisma SD-WAN > Monitor > Sites > [Site] > Applications — check per-app loss'] },
        { gui: ['Prisma SD-WAN > Configure > Policies > Path Selection > [Policy] — prefer lower-loss path', 'Prisma SD-WAN > Configure > Policies > QoS > [Policy] — adjust bandwidth allocation'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — loss percentage decreasing'] },
        ['Path selection changes affect new flows only — existing flows continue on current path'],
        { documentationLinks: [{ title: 'Prisma SD-WAN QoS', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }] },
      ),
      tcp_retransmission: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — check latency', 'Prisma SD-WAN > Monitor > Sites > [Site] > Links — check jitter'] },
        { gui: ['Prisma SD-WAN > Configure > Policies > Application QoS > [App] — set priority', 'Prisma SD-WAN > Configure > Policies > Path Selection — prefer lower-latency path'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — latency improving'] },
        ['Application QoS changes take 2-5 minutes to propagate'],
        { documentationLinks: [{ title: 'Prisma SD-WAN Application Policy', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }] },
      ),
      ddos_syn_flood: fb(
        { gui: ['Prisma SD-WAN > Monitor > Alerts — check for security alerts', 'Prisma SD-WAN > Monitor > Sites > [Site] > Events — check for anomalies'] },
        { gui: ['Prisma SD-WAN > Configure > Security > Zone Firewall > Add Rule > Block source IP', 'Prisma SD-WAN > Configure > Security > Enable IDS/IPS (if licensed with Prisma Access)'] },
        { gui: ['Prisma SD-WAN > Monitor > Alerts — attack traffic blocked'] },
        ['Zone firewall rules are per-site — create at network policy level for network-wide block'],
        { documentationLinks: [{ title: 'Prisma SD-WAN Security', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }] },
      ),
      c2_beaconing: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — look for unknown apps with regular intervals'] },
        { gui: ['Prisma SD-WAN > Configure > Security > Zone Firewall > Block destination IP <C2_IP>'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — no new connections to C2 IP'] },
        ['CRITICAL: Isolate the infected host FIRST', 'Preserve all logs for forensic investigation'],
        { documentationLinks: [{ title: 'Prisma SD-WAN Security', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }] },
      ),
      dns_tunneling: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — filter DNS traffic'] },
        { gui: ['Prisma SD-WAN > Configure > Security > DNS Security > Block suspicious domain (requires Prisma Access)'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — DNS traffic to suspicious domain stopped'] },
        ['DNS tunneling indicates active data exfiltration — treat as P1 security incident', 'DNS Security requires Prisma Access integration'],
        { documentationLinks: [{ title: 'Prisma SD-WAN DNS Security', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }] },
      ),
      port_scan: fb(
        { gui: ['Prisma SD-WAN > Monitor > Alerts — check for security anomalies', 'Prisma SD-WAN > Monitor > Sites > [Site] > Events — filter by source IP'] },
        { gui: ['Prisma SD-WAN > Configure > Security > Zone Firewall > Add Rule > Block source IP'] },
        { gui: ['Prisma SD-WAN > Monitor > Alerts — scanner IP blocked'] },
        ['Verify the source is not an authorized vulnerability scanner before blocking', 'Zone firewall rules are per-site — create at network policy level for network-wide block'],
      ),
      tcp_handshake_failure: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — check path to destination', 'Prisma SD-WAN > Monitor > Sites > [Site] > Events — check for routing changes', 'Prisma SD-WAN > Monitor > Sites > [Site] > Applications — filter by destination'], cli: ['show vpn status', 'show interface status'] },
        { gui: ['Prisma SD-WAN > Configure > Policies > Path Selection — verify path to destination', 'Prisma SD-WAN > Configure > Security > Zone Firewall — verify no rule blocks destination'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — connections succeeding'] },
        ['Check if the destination is reachable through the SD-WAN overlay', 'Zone firewall rules may block the destination port'],
      ),
      arp_conflict: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — check for ARP events'], cli: ['show arp'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — identify conflicting MACs', 'Enable DHCP snooping and DAI on the LAN switch'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — no ARP conflicts'] },
        ['ARP conflicts are LAN-side — configure DAI on the LAN switch, not the ION appliance'],
      ),
      voip_quality: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — check jitter/loss per link', 'Prisma SD-WAN > Monitor > Sites > [Site] > Applications — filter voice/RTP traffic'] },
        { gui: ['Prisma SD-WAN > Configure > Policies > Application QoS > Voice/RTP — set Real-Time priority', 'Prisma SD-WAN > Configure > Policies > Path Selection > Voice — prefer best quality path'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — voice quality improved'] },
        ['Voice traffic must be classified as Real-Time in Application QoS', 'Path selection changes take 2-5 minutes to propagate'],
        { tacNotes: ['Collect diagnostic bundle and application metrics from Prisma SD-WAN portal'] },
      ),
      dhcp_rogue_server: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — check DHCP events'] },
        { gui: ['Prisma SD-WAN > Configure > Sites > [Site] > DHCP — verify DHCP server settings', 'Enable DHCP snooping on the LAN switch'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — no rogue DHCP'] },
        ['DHCP snooping must be configured on the LAN switch, not the ION appliance'],
      ),
      ntp_amplification: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — check for NTP anomalies', 'Prisma SD-WAN > Monitor > Alerts — check bandwidth spikes'] },
        { gui: ['Prisma SD-WAN > Configure > Security > Zone Firewall > Rate-limit or block NTP from external sources', 'Prisma SD-WAN > Configure > Sites > [Site] > NTP — verify NTP server list'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — NTP traffic normalized'] },
        ['Block NTP amplification at the perimeter first'],
      ),
      tcp_zero_window: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — check utilization', 'Prisma SD-WAN > Monitor > Sites > [Site] > Applications — check affected flows'] },
        { gui: ['Prisma SD-WAN > Configure > Policies > QoS — ensure sufficient bandwidth allocation', 'Check application server CPU/memory — Zero Window is usually receiver-side'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — utilization normalized'] },
        ['Zero Window is usually a receiver-side application problem, not an SD-WAN issue'],
      ),
      tcp_out_of_order: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — check if traffic is split across links', 'Prisma SD-WAN > Monitor > Sites > [Site] > Applications — check affected flows'] },
        { gui: ['Prisma SD-WAN > Configure > Policies > Path Selection — use single path for sensitive flows'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Applications — OOO packets decreasing'] },
        ['Multi-path routing may cause OOO — use single-path for latency-sensitive apps'],
      ),
      tls_weakness: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — check for TLS warnings', 'Prisma SD-WAN > Administration > Settings > TLS — check minimum version'] },
        { gui: ['Prisma SD-WAN > Administration > Settings > TLS — set minimum TLS 1.2', 'Contact the server administrator to update TLS configuration'] },
        { gui: ['Prisma SD-WAN > Administration > Settings — TLS 1.2+ enforced'] },
        ['TLS weakness is usually on the server side, not the ION appliance', 'Changing portal TLS settings affects management connectivity'],
      ),
      hsrp_instability: fb(
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — check for gateway changes'], cli: ['show interface status'] },
        { gui: ['Prisma SD-WAN > Configure > Sites > [Site] > WAN Interfaces — verify gateway IP', 'Configure HSRP/VRRP preempt delay on the LAN routers'] },
        { gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Events — no gateway flap events'] },
        ['HSRP/VRRP is configured on LAN routers, not the ION appliance'],
      ),
      high_rtt: fb(
        {
          gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — check latency per link', 'Prisma SD-WAN > Monitor > Sites > [Site] > Applications — check per-app latency', 'Prisma SD-WAN > Monitor > Insights > Application Performance — check SaaS app latency'],
        },
        {
          gui: ['Prisma SD-WAN > Configure > Policies > Path Selection > [Policy] — prefer lower-latency path', 'Prisma SD-WAN > Configure > Policies > Application QoS > [App] — set priority for latency-sensitive apps'],
        },
        {
          gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — latency decreasing', 'Prisma SD-WAN > Monitor > Insights > Application Performance — app latency improving'],
        },
        ['High RTT may be underlay ISP issue — check link quality probes first', 'Path selection changes take 2-5 minutes to propagate to ION appliances'],
        { documentationLinks: [{ title: 'Prisma SD-WAN Path Selection', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }] },
      ),
      prisma_access_integration: fb(
        {
          gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Tunnels — check Prisma Access tunnel status', 'Prisma SD-WAN > Monitor > Alerts — check for Prisma Access connectivity alerts', 'Prisma Access > Monitor > Remote Networks — check SD-WAN site connectivity', 'Prisma SD-WAN > Configure > Network > Service Links — check Prisma Access service link status'],
          script: ['# API: Check Prisma Access tunnel status', 'curl -H "Authorization: Bearer <token>" "https://api.sase.paloaltonetworks.com/sdwan/v2.0/api/sites/<site_id>/tunnels"'],
        },
        {
          gui: ['Prisma SD-WAN > Configure > Network > Service Links > [Prisma Access Link] — verify configuration', 'Prisma SD-WAN > Configure > Policies > Path Selection — verify Prisma Access is in path selection', 'Prisma Access > Configure > Remote Networks > [Site] — verify SD-WAN site configuration', 'Prisma SD-WAN > Configure > Sites > [Site] > WAN Interfaces — verify public IP for Prisma Access tunnel'],
        },
        {
          gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Tunnels — Prisma Access tunnel "Up"', 'Prisma Access > Monitor > Remote Networks — site connected'],
        },
        ['Prisma Access integration requires separate licensing — verify license status first', 'Prisma Access tunnels require public IP or NAT traversal on the ION appliance', 'If Prisma Access tunnel is down, traffic may bypass cloud security — check path selection fallback policy', 'Prisma Access and Prisma SD-WAN are managed in different portals — check both'],
        {
          documentationLinks: [
            { title: 'Prisma SD-WAN + Prisma Access', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan/prisma-access-integration' },
            { title: 'Prisma Access Admin Guide', url: 'https://docs.paloaltonetworks.com/prisma-access' },
          ],
          tacNotes: ['Collect tunnel status from both Prisma SD-WAN and Prisma Access portals', 'Include service link configuration and site events'],
        },
      ),
      saas_app_performance: fb(
        {
          gui: ['Prisma SD-WAN > Monitor > Insights > Application Performance — check SaaS app metrics', 'Prisma SD-WAN > Monitor > Sites > [Site] > Applications — filter by SaaS app (Office 365, Salesforce, etc.)', 'Prisma SD-WAN > Monitor > Sites > [Site] > Links — check link quality for SaaS traffic'],
        },
        {
          gui: ['Prisma SD-WAN > Configure > Policies > Application QoS > [SaaS App] — set Real-Time or Interactive priority', 'Prisma SD-WAN > Configure > Policies > Path Selection > [SaaS App] — prefer best quality path', 'Prisma SD-WAN > Configure > Network > Direct Internet Access — enable DIA for SaaS apps (bypass backhaul)', 'Prisma SD-WAN > Configure > Policies > Application Definitions — verify SaaS app is correctly classified'],
        },
        {
          gui: ['Prisma SD-WAN > Monitor > Insights > Application Performance — SaaS app metrics improving', 'Prisma SD-WAN > Monitor > Sites > [Site] > Applications — SaaS app latency/loss decreasing'],
        },
        ['SaaS app performance often improves with Direct Internet Access (DIA) — avoid backhauling SaaS traffic through the data center', 'Application classification must be correct for QoS to work — verify the app is recognized', 'Prisma Access can provide optimized paths to SaaS apps — consider enabling if licensed', 'Some SaaS apps use multiple domains/IPs — ensure all are covered in the application definition'],
        {
          documentationLinks: [{ title: 'Prisma SD-WAN Application QoS', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }],
          tacNotes: ['Collect application performance metrics from Prisma SD-WAN Insights', 'Include path selection policy and application definition configuration'],
        },
      ),
      link_quality_degradation: fb(
        {
          gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — check link quality metrics (latency, loss, jitter)', 'Prisma SD-WAN > Monitor > Sites > [Site] > Links > [Link] > Quality History — check trends', 'Prisma SD-WAN > Monitor > Alerts — check for link quality alerts'],
          cli: ['show interface status', 'show vpn status'],
        },
        {
          gui: ['Prisma SD-WAN > Configure > Sites > [Site] > WAN Interfaces > [Link] — adjust bandwidth settings', 'Prisma SD-WAN > Configure > Policies > Path Selection — adjust path preference to avoid degraded link', 'Prisma SD-WAN > Configure > Sites > [Site] > WAN Interfaces > [Link] > Quality Probes — adjust probe settings'],
        },
        {
          gui: ['Prisma SD-WAN > Monitor > Sites > [Site] > Links — link quality improving', 'Prisma SD-WAN > Monitor > Alerts — no link quality alerts'],
        },
        ['Link quality degradation is usually an ISP issue — contact ISP if metrics are consistently bad', 'Quality probes measure link health independently of user traffic — probe failures indicate real link issues', 'Path selection automatically avoids degraded links if configured — verify path selection policy', 'Bandwidth settings affect QoS scheduling — ensure they match actual link capacity'],
        {
          documentationLinks: [{ title: 'Prisma SD-WAN Link Quality', url: 'https://docs.paloaltonetworks.com/prisma-sd-wan' }],
          tacNotes: ['Collect link quality history from Prisma SD-WAN portal', 'Include WAN interface configuration and quality probe settings'],
        },
      ),
    },
  },

  // ═══════════════════════════════════════════════════════════════
  // CITRIX SD-WAN — GUI-primary
  // ═══════════════════════════════════════════════════════════════
  'Citrix SD-WAN': {
    vendor: 'Citrix SD-WAN',
    vendorKey: 'citrix',
    logo: 'X',
    color: 'text-indigo-400',
    bgColor: 'bg-indigo-500/10',
    borderColor: 'border-indigo-500/20',
    primaryInterface: 'gui',
    defaultUrl: 'https://<sd-wan-center-ip>',
    authentication: 'Log in to Citrix SD-WAN Center or MCN (Master Control Node) web UI. For appliance CLI: SSH as admin@<appliance-ip>.',
    gettingStarted: {
      primer: 'Citrix SD-WAN uses the SD-WAN Center as the centralized management GUI and MCN (Master Control Node) as the primary controller. Branch appliances connect to the MCN. The platform supports WAN optimization and HDX QoS for Citrix Virtual Apps.',
      interfaceNote: 'GUI-primary platform. Use SD-WAN Center for monitoring and configuration. MCN web UI for detailed appliance management. Limited CLI available via SSH.',
      loginInfo: 'SD-WAN Center: https://<sd-wan-center-ip> (admin credentials). MCN: https://<mcn-ip>. Appliance CLI: ssh admin@<appliance-ip>',
      commonMistakes: [
        'Configuration changes in SD-WAN Center must be staged and activated — they do not apply immediately',
        'MCN is the single point of control — if MCN goes down, branch appliances continue forwarding but cannot be managed',
        'HDX QoS requires proper Citrix ICA classification — verify AppFlow is enabled',
        'Virtual WAN paths are different from physical WAN links — check both when troubleshooting',
      ],
      quickLinks: [
        { title: 'Citrix SD-WAN Documentation', url: 'https://docs.citrix.com/en-us/citrix-sd-wan.html' },
        { title: 'Citrix SD-WAN Center Guide', url: 'https://docs.citrix.com/en-us/citrix-sd-wan-center.html' },
        { title: 'Citrix Support', url: 'https://support.citrix.com/' },
      ],
    },
    findings: {
      tunnel_flapping: fb(
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — check path state history', 'SD-WAN Center > Monitoring > Virtual WAN > WAN Links — check link health', 'MCN > Monitor > Statistics > Virtual Paths — check path status'], cli: ['show virtual-path', 'show wan-link', 'show dynamic-virtual-path'] },
        { gui: ['SD-WAN Center > Configuration > Virtual WAN > WAN Links > [Link] — adjust dead interval', 'MCN > Configuration > Virtual WAN > Virtual Path Settings — adjust keepalive timers'], cli: ['! Adjust path keepalive via GUI — CLI is read-only for most settings'] },
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — all paths "Good" for 5+ minutes', 'MCN > Monitor > Statistics > Virtual Paths — stable'], cli: ['show virtual-path'] },
        ['Configuration changes must be staged and activated — do not skip the activation step', 'MCN path changes affect all connected branch appliances'],
        { recommendedVersions: ['Citrix SD-WAN 11.4.x (recommended)', 'SD-WAN Center 11.4.x'], documentationLinks: [{ title: 'Citrix SD-WAN Virtual Path', url: 'https://docs.citrix.com/en-us/citrix-sd-wan.html' }], tacNotes: ['Collect diagnostic package from SD-WAN Center', 'Include path statistics from both endpoints'] },
      ),
      packet_loss: fb(
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — check loss percentage', 'MCN > Monitor > Statistics > WAN Links — check per-link loss'], cli: ['show wan-link', 'show virtual-path | include loss'] },
        { gui: ['SD-WAN Center > Configuration > Virtual WAN > Rules > [Rule] — enable packet duplication for critical apps', 'MCN > Configuration > QoS — adjust bandwidth allocation'] },
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — loss decreasing'], cli: ['show virtual-path | include loss'] },
        ['Packet duplication doubles bandwidth usage — only enable for critical traffic'],
      ),
      tcp_retransmission: fb(
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — check latency/jitter', 'MCN > Monitor > Statistics > Applications — check affected apps'], cli: ['show virtual-path', 'show application'] },
        { gui: ['SD-WAN Center > Configuration > Virtual WAN > Rules > [Rule] — set preferred path to lower-latency link', 'MCN > Configuration > QoS > Application Rules — prioritize affected app'] },
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — latency improving'] },
        ['Rule changes must be staged and activated'],
      ),
      ddos_syn_flood: fb(
        { gui: ['SD-WAN Center > Monitoring > Firewall — check blocked connections', 'MCN > Monitor > Firewall > Statistics — check for anomalies'], cli: ['show firewall statistics'] },
        { gui: ['SD-WAN Center > Configuration > Firewall > Add Rule > Block source IP', 'MCN > Configuration > Firewall > Policies > Add deny rule'] },
        { gui: ['SD-WAN Center > Monitoring > Firewall — attack traffic blocked'] },
        ['Firewall rules must be staged and activated'],
      ),
      c2_beaconing: fb(
        { gui: ['SD-WAN Center > Monitoring > Applications — look for regular interval connections', 'MCN > Monitor > Statistics > Flows — filter by destination IP'] },
        { gui: ['SD-WAN Center > Configuration > Firewall > Add Rule > Block destination IP <C2_IP>'] },
        { gui: ['SD-WAN Center > Monitoring > Applications — no new connections to C2 IP'] },
        ['CRITICAL: Isolate the infected host FIRST', 'Preserve all logs for forensic investigation'],
      ),
      dns_tunneling: fb(
        { gui: ['SD-WAN Center > Monitoring > Applications — filter DNS traffic', 'MCN > Monitor > Statistics > Flows — filter port 53'], cli: ['show application | include DNS'] },
        { gui: ['SD-WAN Center > Configuration > Firewall > Add Rule > Block DNS to suspicious domain'] },
        { gui: ['SD-WAN Center > Monitoring > Applications — DNS to suspicious domain stopped'] },
        ['DNS tunneling indicates active data exfiltration — treat as P1 security incident'],
      ),
      port_scan: fb(
        { gui: ['SD-WAN Center > Monitoring > Firewall — check for blocked connections from scanner', 'MCN > Monitor > Firewall > Statistics — filter by source IP'], cli: ['show firewall statistics'] },
        { gui: ['SD-WAN Center > Configuration > Firewall > Add Rule > Block source IP'] },
        { gui: ['SD-WAN Center > Monitoring > Firewall — scanner blocked'] },
        ['Verify the source is not an authorized vulnerability scanner before blocking'],
      ),
      tcp_handshake_failure: fb(
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — check path to destination', 'MCN > Monitor > Statistics > Flows — filter by destination IP'], cli: ['show virtual-path', 'show route'] },
        { gui: ['SD-WAN Center > Configuration > Virtual WAN > Routes — verify route to destination', 'SD-WAN Center > Configuration > Firewall — verify no rule blocks destination'] },
        { gui: ['SD-WAN Center > Monitoring > Applications — connections to destination succeeding'] },
        ['Check if the destination is reachable through the virtual WAN overlay'],
      ),
      arp_conflict: fb(
        { gui: ['MCN > Monitor > Appliance > ARP Table — check for duplicate IPs'], cli: ['show arp'] },
        { gui: ['MCN > Monitor > Appliance > ARP Table — identify conflicting MACs', 'Enable DAI on the LAN switch'] },
        { gui: ['MCN > Monitor > Appliance > ARP Table — single MAC per IP'] },
        ['ARP conflicts are LAN-side — configure DAI on the LAN switch, not the SD-WAN appliance'],
      ),
      voip_quality: fb(
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — check jitter/loss', 'MCN > Monitor > Statistics > Applications — filter voice/RTP', 'MCN > Monitor > HDX — check Citrix ICA voice quality'], cli: ['show application | include voice\\|RTP'] },
        { gui: ['SD-WAN Center > Configuration > Virtual WAN > Rules > Voice — set Real-Time class', 'MCN > Configuration > QoS > HDX — enable HDX QoS for ICA voice'] },
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — voice quality improved', 'MCN > Monitor > HDX — ICA voice quality good'] },
        ['HDX QoS provides special optimization for Citrix ICA traffic including voice', 'Ensure AppFlow is enabled for proper application classification'],
        { tacNotes: ['Collect diagnostic package and HDX statistics from SD-WAN Center'] },
      ),
      dhcp_rogue_server: fb(
        { gui: ['MCN > Monitor > Appliance > DHCP — check DHCP server status'], cli: ['show dhcp'] },
        { gui: ['MCN > Configuration > Appliance > DHCP — verify server settings', 'Enable DHCP snooping on the LAN switch'] },
        { gui: ['MCN > Monitor > Appliance > DHCP — only authorized server responding'] },
        ['DHCP snooping must be configured on the LAN switch, not the SD-WAN appliance'],
      ),
      ntp_amplification: fb(
        { gui: ['SD-WAN Center > Monitoring > Applications — filter UDP port 123', 'MCN > Monitor > Statistics > Flows — filter NTP'], cli: ['show ntp'] },
        { gui: ['SD-WAN Center > Configuration > Firewall > Rate-limit NTP', 'MCN > Configuration > Appliance > NTP — verify server list'] },
        { gui: ['SD-WAN Center > Monitoring > Applications — NTP traffic normalized'] },
        ['Block NTP amplification at the perimeter first'],
      ),
      tcp_zero_window: fb(
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — check latency spikes', 'MCN > Monitor > Statistics > Applications — check affected flows'] },
        { gui: ['MCN > Configuration > QoS — ensure sufficient bandwidth allocation', 'Check application server CPU/memory'] },
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — latency normalized'] },
        ['Zero Window is usually a receiver-side application problem, not an SD-WAN issue'],
      ),
      tcp_out_of_order: fb(
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — check if traffic is split across paths', 'MCN > Monitor > Statistics > Virtual Paths — check per-path metrics'] },
        { gui: ['SD-WAN Center > Configuration > Virtual WAN > Rules — use single path for sensitive flows'] },
        { gui: ['SD-WAN Center > Monitoring > Virtual WAN > Paths — OOO packets decreasing'] },
        ['Multi-path virtual WAN may cause OOO — use single-path rules for sensitive apps'],
      ),
      tls_weakness: fb(
        { gui: ['MCN > Administration > SSL Settings — check minimum TLS version'], cli: ['show ssl'] },
        { gui: ['MCN > Administration > SSL Settings — set minimum TLS 1.2', 'Contact the server administrator to update TLS configuration'] },
        { gui: ['MCN > Administration > SSL Settings — TLS 1.2+ enforced'] },
        ['TLS weakness is usually on the server side, not the SD-WAN appliance'],
      ),
      hsrp_instability: fb(
        { gui: ['MCN > Monitor > Appliance > Routes — check for gateway changes'], cli: ['show route', 'show arp | include <gateway_ip>'] },
        { gui: ['MCN > Configuration > Appliance > WAN Links — verify gateway IP', 'Configure HSRP/VRRP preempt delay on the LAN routers'] },
        { gui: ['MCN > Monitor > Appliance > Routes — gateway stable'] },
        ['HSRP/VRRP is configured on LAN routers, not the SD-WAN appliance'],
      ),
    },
  },

  // ═══════════════════════════════════════════════════════════════
  // VERSA NETWORKS — Hybrid
  // ═══════════════════════════════════════════════════════════════
  'Versa Networks': {
    vendor: 'Versa Networks SD-WAN',
    vendorKey: 'versa',
    logo: 'N',
    color: 'text-teal-400',
    bgColor: 'bg-teal-500/10',
    borderColor: 'border-teal-500/20',
    primaryInterface: 'hybrid',
    defaultUrl: 'https://<versa-director-ip>:9182',
    authentication: 'Log in to Versa Director web UI. For FlexVNF CLI: SSH as admin@<flexvnf-ip>.',
    gettingStarted: {
      primer: 'Versa Networks uses Versa Director as the centralized management and orchestration platform, and Versa Analytics for monitoring. FlexVNF appliances run at each site and support VNF chaining (firewall, SD-WAN, routing in one box). The CLI is Versa OS based.',
      interfaceNote: 'Hybrid platform. Use Versa Director GUI for configuration and policy management. Use Versa Analytics for monitoring. Use FlexVNF CLI for real-time diagnostics.',
      loginInfo: 'Versa Director: https://<director-ip>:9182 (admin credentials). FlexVNF CLI: ssh admin@<flexvnf-ip>. Versa Analytics: https://<analytics-ip>:8443',
      commonMistakes: [
        'Versa Director template changes require a commit and deploy — they do not auto-push',
        'FlexVNF supports multiple VNFs (SD-WAN, NGFW, routing) — ensure you are troubleshooting the correct VNF',
        'Versa Analytics data may have a 2-5 minute delay — do not assume real-time accuracy',
        'SASE integration requires Versa SASE Gateway — verify licensing before troubleshooting',
      ],
      quickLinks: [
        { title: 'Versa Networks Documentation', url: 'https://docs.versa-networks.com/' },
        { title: 'Versa Director Guide', url: 'https://docs.versa-networks.com/director' },
        { title: 'Versa Support Portal', url: 'https://support.versa-networks.com/' },
      ],
    },
    findings: {
      tunnel_flapping: fb(
        { cli: ['show interfaces sdwan', 'show sdwan tunnels', 'show sdwan peers', 'show bfd sessions', 'show alarms'], gui: ['Director > Monitor > Appliances > [Appliance] > SD-WAN > Tunnels — check tunnel state', 'Analytics > SD-WAN > Tunnels — check tunnel history', 'Director > Monitor > Appliances > [Appliance] > Alarms'] },
        { cli: ['set sdwan tunnel <name> keepalive-interval 10', 'commit'], gui: ['Director > Configuration > Templates > [Template] > SD-WAN > Tunnel Settings — adjust keepalive', 'Director > Workflows > Deploy Template'] },
        { cli: ['show sdwan tunnels', 'show bfd sessions', 'show alarms'], gui: ['Director > Monitor > Appliances > [Appliance] > SD-WAN > Tunnels — all "Up"', 'Analytics > SD-WAN > Tunnels — stable'] },
        ['Template changes require commit and deploy', 'BFD timer changes affect all tunnels using that profile'],
        { recommendedVersions: ['Versa OS 22.1.x (recommended)', 'Director 22.1.x'], documentationLinks: [{ title: 'Versa SD-WAN Configuration', url: 'https://docs.versa-networks.com/' }], tacNotes: ['Collect "request support information" from both endpoints', 'Include tunnel and BFD statistics'] },
      ),
      packet_loss: fb(
        { cli: ['show sdwan tunnels | include loss', 'show interfaces sdwan statistics', 'show sdwan app-route'], gui: ['Analytics > SD-WAN > Tunnels — check loss per tunnel', 'Director > Monitor > Appliances > [Appliance] > Interfaces — check drops'] },
        { cli: ['set sdwan policy app-route <name> sla loss-threshold 1', 'commit'], gui: ['Director > Configuration > Policies > App-Route Policy > SLA — adjust loss threshold'] },
        { cli: ['show sdwan tunnels | include loss', 'show sdwan app-route'], gui: ['Analytics > SD-WAN > Tunnels — loss decreasing'] },
        ['FEC adds bandwidth overhead — ensure sufficient WAN capacity'],
      ),
      tcp_retransmission: fb(
        { cli: ['show sdwan app-route', 'show sdwan tunnels', 'show interfaces sdwan statistics'], gui: ['Analytics > SD-WAN > App Route — check latency/jitter', 'Director > Monitor > Appliances > [Appliance] > SD-WAN > App Route'] },
        { cli: ['set sdwan policy app-route <name> sla latency-threshold 100 jitter-threshold 30', 'commit'], gui: ['Director > Configuration > Policies > App-Route Policy > SLA — adjust thresholds'] },
        { cli: ['show sdwan app-route'], gui: ['Analytics > SD-WAN > App Route — latency improving'] },
        ['SLA threshold changes trigger immediate path re-evaluation'],
      ),
      ddos_syn_flood: fb(
        { cli: ['show security flow statistics', 'show security zones', 'show security policies hit-count'], gui: ['Analytics > Security > Threats — check for DDoS events', 'Director > Monitor > Appliances > [Appliance] > Security > Firewall'] },
        { cli: ['set security policy <name> rule BLOCK-DDOS match source-address <attacker_ip> then deny', 'commit'], gui: ['Director > Configuration > Security > Firewall Policy > Add deny rule for attacker IP'] },
        { cli: ['show security policies hit-count'], gui: ['Analytics > Security > Threats — attack traffic blocked'] },
        ['Security policy changes require commit and deploy'],
      ),
      c2_beaconing: fb(
        { cli: ['show security flow statistics | include <C2_IP>', 'show sdwan flows | include <C2_IP>'], gui: ['Analytics > Security > Flows — filter by destination IP, look for regular intervals'] },
        { cli: ['set security policy <name> rule BLOCK-C2 match destination-address <C2_IP> then deny', 'commit'], gui: ['Director > Configuration > Security > Firewall Policy > Block destination IP <C2_IP>'] },
        { cli: ['show security flow statistics | include <C2_IP>  ! Should return empty'] },
        ['CRITICAL: Isolate the infected host FIRST', 'Preserve all logs for forensic investigation'],
      ),
      dns_tunneling: fb(
        { cli: ['show sdwan flows | include ":53"', 'show dns statistics'], gui: ['Analytics > Security > DNS — check for suspicious domains'] },
        { cli: ['set security policy <name> rule BLOCK-DNS match destination-port 53 destination-address <suspicious-domain> then deny', 'commit'], gui: ['Director > Configuration > Security > DNS Security > Block suspicious domain'] },
        { cli: ['show sdwan flows | include ":53"'] },
        ['DNS tunneling indicates active data exfiltration — treat as P1 security incident'],
      ),
      port_scan: fb(
        { cli: ['show security flow statistics | include <scanner_ip>', 'show security ips statistics'], gui: ['Analytics > Security > Threats — filter by source IP', 'Director > Monitor > Appliances > [Appliance] > Security > IPS'] },
        { cli: ['set security policy <name> rule BLOCK-SCANNER match source-address <scanner_ip> then deny', 'commit'], gui: ['Director > Configuration > Security > Firewall Policy > Block scanner IP'] },
        { cli: ['show security flow statistics | include <scanner_ip>  ! Should return empty'] },
        ['Verify the source is not an authorized vulnerability scanner before blocking', 'Versa NGFW IPS can detect and block port scans automatically'],
      ),
      tcp_handshake_failure: fb(
        { cli: ['show sdwan tunnels', 'show routing table | include <dest_ip>', 'show sdwan flows | include <dest_ip>'], gui: ['Director > Monitor > Appliances > [Appliance] > Routing — check route to destination', 'Analytics > SD-WAN > Flows — filter by destination'] },
        { cli: ['! Verify routing and security policy', 'show security policies hit-count | include <dest_ip>', 'show routing table <dest_ip>'], gui: ['Director > Configuration > Security > Firewall Policy — verify no rule blocks destination'] },
        { cli: ['show sdwan flows | include <dest_ip>'], gui: ['Analytics > SD-WAN > Flows — connections to destination succeeding'] },
        ['Check both SD-WAN routing and NGFW security policies', 'VNF chaining order matters — verify traffic flow through VNFs'],
      ),
      arp_conflict: fb(
        { cli: ['show arp', 'show interfaces'], gui: ['Director > Monitor > Appliances > [Appliance] > ARP — check for duplicates'] },
        { cli: ['clear arp', '! Enable DAI on the LAN switch'] },
        { cli: ['show arp | include <conflict_ip>'], gui: ['Director > Monitor > Appliances > [Appliance] > ARP — single MAC per IP'] },
        ['ARP conflicts are LAN-side — configure DAI on the LAN switch, not FlexVNF'],
      ),
      voip_quality: fb(
        { cli: ['show sdwan app-route', 'show sdwan tunnels | include loss|jitter', 'show qos statistics'], gui: ['Analytics > SD-WAN > App Route — check voice SLA', 'Analytics > Applications > Voice/RTP — check quality metrics'] },
        { cli: ['set sdwan policy app-route VOICE-SLA sla loss-threshold 1 latency-threshold 150 jitter-threshold 30', 'set sdwan policy traffic-rule VOICE match application voice then app-route VOICE-SLA', 'commit'], gui: ['Director > Configuration > Policies > App-Route Policy > Add VOICE-SLA', 'Director > Configuration > Policies > Traffic Rules > Voice > Apply VOICE-SLA'] },
        { cli: ['show sdwan app-route | include voice', 'show qos statistics'], gui: ['Analytics > SD-WAN > App Route — voice SLA met'] },
        ['Voice traffic should be DSCP EF (46) — verify QoS marking in traffic rules', 'App-route policy changes require commit and deploy'],
        { tacNotes: ['Collect app-route statistics and QoS counters from both endpoints'] },
      ),
      dhcp_rogue_server: fb(
        { cli: ['show dhcp server', 'show sdwan flows | include ":67\\|:68"'], gui: ['Director > Monitor > Appliances > [Appliance] > DHCP — check server status'] },
        { cli: ['! Enable DHCP snooping on the LAN switch', 'show dhcp server'], gui: ['Director > Configuration > Appliances > [Appliance] > DHCP — verify server settings'] },
        { cli: ['show dhcp server'], gui: ['Director > Monitor > Appliances > [Appliance] > DHCP — only authorized server'] },
        ['DHCP snooping must be configured on the LAN switch, not FlexVNF'],
      ),
      ntp_amplification: fb(
        { cli: ['show ntp status', 'show sdwan flows | include ":123"'], gui: ['Analytics > Applications — filter UDP port 123'] },
        { cli: ['set system ntp server-mode disable', 'commit', '! Rate-limit NTP via security policy'], gui: ['Director > Configuration > System > NTP — disable NTP server mode'] },
        { cli: ['show ntp status'], gui: ['Analytics > Applications — NTP traffic normalized'] },
        ['Block NTP amplification at the perimeter first'],
      ),
      tcp_zero_window: fb(
        { cli: ['show system resources', 'show interfaces statistics'], gui: ['Director > Monitor > Appliances > [Appliance] > System — check CPU/memory'] },
        { cli: ['! Zero Window is receiver-side — check application server', 'show system resources'], gui: ['Director > Monitor > Appliances > [Appliance] > System — verify resources normal'] },
        { cli: ['show system resources', 'show interfaces statistics'] },
        ['Zero Window is usually a receiver-side application problem, not FlexVNF'],
      ),
      tcp_out_of_order: fb(
        { cli: ['show sdwan tunnels', 'show sdwan app-route', 'show routing table'], gui: ['Analytics > SD-WAN > Tunnels — check if traffic is split across tunnels', 'Director > Monitor > Appliances > [Appliance] > SD-WAN > App Route'] },
        { cli: ['! Ensure per-flow load balancing', 'set sdwan policy traffic-rule <name> load-balance per-flow', 'commit'], gui: ['Director > Configuration > Policies > Traffic Rules — set per-flow load balancing'] },
        { cli: ['show sdwan app-route'], gui: ['Analytics > SD-WAN > App Route — OOO decreasing'] },
        ['Per-packet load balancing causes OOO — use per-flow or per-session'],
      ),
      tls_weakness: fb(
        { cli: ['show system ssl', 'show security tls-profiles'], gui: ['Director > Administration > SSL Settings — check minimum TLS version'] },
        { cli: ['set system ssl min-version tls1.2', 'commit'], gui: ['Director > Administration > SSL Settings — set minimum TLS 1.2'] },
        { cli: ['show system ssl'], gui: ['Director > Administration > SSL Settings — TLS 1.2+ enforced'] },
        ['Changing TLS version may temporarily disconnect management sessions', 'TLS weakness is usually on the server side, not FlexVNF'],
      ),
      hsrp_instability: fb(
        { cli: ['show arp | include <gateway_ip>', 'show routing table', 'show alarms'], gui: ['Director > Monitor > Appliances > [Appliance] > Routing — check gateway'] },
        { cli: ['! Configure gateway monitoring', 'set routing static-route <gateway_ip>/32 next-hop <gateway_ip>', 'commit'], gui: ['Director > Configuration > Routing > Static Routes — verify gateway'] },
        { cli: ['show routing table', 'show alarms'], gui: ['Director > Monitor > Appliances > [Appliance] > Routing — gateway stable'] },
        ['HSRP/VRRP is configured on LAN routers, not FlexVNF'],
      ),
    },
  },
};

// Get the best matching vendor runbook for detected SD-WAN vendors
export function getVendorRunbook(vendorName: string): VendorRunbook | null {
  for (const [key, runbook] of Object.entries(vendorRunbooks)) {
    if (vendorName.toLowerCase().includes(key.toLowerCase()) ||
        key.toLowerCase().includes(vendorName.toLowerCase())) {
      return runbook;
    }
  }
  const lowerName = vendorName.toLowerCase();
  // Cisco SD-WAN (Viptela) — detect vEdge, cEdge, vManage, vSmart, vBond, TLOC, OMP
  if (lowerName.includes('cisco') || lowerName.includes('viptela') || lowerName.includes('vmanage') ||
      lowerName.includes('vedge') || lowerName.includes('cedge') || lowerName.includes('vsmart') ||
      lowerName.includes('vbond') || lowerName.includes('tloc') || lowerName.includes('omp')) return vendorRunbooks['Cisco SD-WAN'];
  // VMware SD-WAN (VeloCloud) — detect VCEdge, VCManager, VCGateway, DMPO
  if (lowerName.includes('vmware') || lowerName.includes('velocloud') || lowerName.includes('velo') ||
      lowerName.includes('vcedge') || lowerName.includes('vcmanager') || lowerName.includes('vcgateway') ||
      lowerName.includes('dmpo') || lowerName.includes('vco')) return vendorRunbooks['VMware SD-WAN'];
  // Aruba SD-WAN (Silver Peak) — detect NX appliances, EdgeConnect, Unity Boost, Orchestrator
  if (lowerName.includes('silver peak') || lowerName.includes('aruba') || lowerName.includes('edgeconnect') ||
      lowerName.includes('silverpeak') || lowerName.includes('unity boost') || lowerName.includes('nx-') ||
      lowerName.includes('ec-') || lowerName.includes('ecos')) return vendorRunbooks['Silver Peak'];
  // Fortinet SD-WAN — detect FortiGate, FortiOS, ADVPN, FortiManager, FortiAnalyzer
  if (lowerName.includes('fortinet') || lowerName.includes('fortigate') || lowerName.includes('fortios') ||
      lowerName.includes('advpn') || lowerName.includes('fortimanager') || lowerName.includes('fortianalyzer') ||
      lowerName.includes('fgt-') || lowerName.includes('fg-')) return vendorRunbooks['Fortinet'];
  // Juniper SD-WAN — detect Session Smart, 128T, Mist, SSR, SVR, Conductor
  if (lowerName.includes('juniper') || lowerName.includes('128t') || lowerName.includes('ssr') ||
      lowerName.includes('mist') || lowerName.includes('session smart') || lowerName.includes('session-smart') ||
      lowerName.includes('svr') || lowerName.includes('conductor') || lowerName.includes('mist edge')) return vendorRunbooks['Juniper'];
  // Palo Alto SD-WAN — detect Prisma, CloudGenix, ION appliances, SASE
  if (lowerName.includes('palo alto') || lowerName.includes('prisma') || lowerName.includes('cloudgenix') ||
      lowerName.includes('ion ') || lowerName.includes('ion-') || lowerName.includes('pan-') ||
      lowerName.includes('cgx') || lowerName.includes('sase')) return vendorRunbooks['Palo Alto'];
  // Citrix SD-WAN — detect NetScaler, SD-WAN Center, MCN, HDX
  if (lowerName.includes('citrix') || lowerName.includes('netscaler') || lowerName.includes('sd-wan center') ||
      lowerName.includes('mcn') || lowerName.includes('hdx')) return vendorRunbooks['Citrix SD-WAN'];
  // Versa Networks — detect FlexVNF, Versa Director, Versa Analytics, SASE Gateway
  if (lowerName.includes('versa') || lowerName.includes('flexvnf') || lowerName.includes('versa-director') ||
      lowerName.includes('versa director') || lowerName.includes('versa analytics')) return vendorRunbooks['Versa Networks'];
  return null;
}

// Get finding-specific runbook for a vendor
export function getVendorFindingRunbook(vendorName: string, findingKey: string): VendorFindingRunbook | null {
  const runbook = getVendorRunbook(vendorName);
  if (!runbook) return null;
  return runbook.findings[findingKey] || null;
}
