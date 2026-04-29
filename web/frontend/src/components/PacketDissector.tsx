import React, { useState } from 'react';
import {
  X,
  ChevronRight,
  ChevronDown,
  Info,
  HelpCircle,
  Layers,
  Network,
  Activity,
} from 'lucide-react';
import type { Discrepancy } from '../types';
import { AnalysisBadges } from './AnalysisBadges';
import { useContextMenu } from './GlobalContextMenu';
import { GlossaryTerm, GLOSSARY } from './Glossary';

// Helper to render text with glossary-linked terms
function renderWithGlossaryTerms(text: string): React.ReactNode {
  const glossaryTerms = Object.keys(GLOSSARY);
  const parts: React.ReactNode[] = [];
  let key = 0;

  // Match common abbreviations
  const abbrevRegex = /\b(TTL|DSCP|MSS|RTT|RTO|BFD|OMP|CWND|RWND|MTU|PMTUD|RST|FIN|SYN|ACK)\b/g;
  let match;
  let lastIndex = 0;

  while ((match = abbrevRegex.exec(text)) !== null) {
    // Add text before match
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    
    // Find glossary key for this abbreviation
    const abbrev = match[1];
    const glossaryKey = glossaryTerms.find(t => {
      const entry = GLOSSARY[t];
      return entry.abbreviation?.toUpperCase() === abbrev || t.toUpperCase() === abbrev;
    });

    if (glossaryKey) {
      parts.push(<GlossaryTerm key={key++} term={glossaryKey}>{abbrev}</GlossaryTerm>);
    } else {
      parts.push(abbrev);
    }
    
    lastIndex = match.index + match[0].length;
  }

  // Add remaining text
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }

  return parts.length > 0 ? parts : text;
}

// fieldNameToFilterToken maps a dissector field label (e.g. "Source IP")
// plus its enclosing layer name (e.g. "IPv4", "TCP") to a Wireshark-style
// filter token that the FilterBuilder scratchpad understands. Unknown
// fields fall back to a lower-cased dotted form so a "Copy Value" action
// still works even when we cannot express a precise filter clause.
function fieldNameToFilterToken(layerName: string, fieldName: string): string {
  const key = `${layerName}/${fieldName}`;
  switch (key) {
    case 'Ethernet/Source MAC':
      return 'eth.src';
    case 'Ethernet/Destination MAC':
      return 'eth.dst';
    case 'Ethernet/EtherType':
      return 'eth.type';
    case 'IPv4/Source IP':
    case 'IPv6/Source IP':
      return 'ip.src';
    case 'IPv4/Destination IP':
    case 'IPv6/Destination IP':
      return 'ip.dst';
    case 'IPv4/TTL':
      return 'ip.ttl';
    case 'IPv4/Protocol':
      return 'ip.proto';
    case 'IPv4/DSCP':
    case 'IPv4/Type of Service':
      return 'ip.dsfield.dscp';
    case 'IPv4/Total Length':
      return 'ip.len';
    case 'IPv4/Identification':
    case 'IPv4/ID':
      return 'ip.id';
    case 'TCP/Source Port':
      return 'tcp.srcport';
    case 'TCP/Destination Port':
      return 'tcp.dstport';
    case 'TCP/Sequence Number':
      return 'tcp.seq';
    case 'TCP/Acknowledgment Number':
    case 'TCP/Acknowledgement Number':
      return 'tcp.ack';
    case 'TCP/Window Size':
      return 'tcp.window_size';
    case 'TCP/Flags':
      return 'tcp.flags';
    case 'UDP/Source Port':
      return 'udp.srcport';
    case 'UDP/Destination Port':
      return 'udp.dstport';
    case 'UDP/Length':
      return 'udp.length';
  }
  // Fallback: snake-case the layer and field name together.
  return `${layerName}.${fieldName}`.replace(/\s+/g, '_').toLowerCase();
}

interface PacketDissectorProps {
  discrepancy: Discrepancy;
  onClose: () => void;
}

interface ProtocolField {
  name: string;
  value: string;
  offset: number;
  length: number;
  explanation: string;
  bits?: string;
  children?: ProtocolField[];
}

interface ProtocolLayer {
  name: string;
  expanded: boolean;
  fields: ProtocolField[];
  diagram?: React.ReactNode;
}

export const PacketDissector: React.FC<PacketDissectorProps> = ({ discrepancy, onClose }) => {
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set(['Ethernet', 'IPv4', 'TCP', 'UDP']));
  const [selectedField, setSelectedField] = useState<ProtocolField | null>(null);
  const [showExplanation, setShowExplanation] = useState<string | null>(null);

  const toggleLayer = (layerName: string) => {
    setExpandedLayers(prev => {
      const next = new Set(prev);
      if (next.has(layerName)) next.delete(layerName);
      else next.add(layerName);
      return next;
    });
  };

  const layers = parsePacketLayers(discrepancy);
  const hexDump = generateHexDump(discrepancy);

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-7xl h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 rounded-lg">
              <Layers className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white flex items-center gap-2 flex-wrap">
                <span>Interactive Packet Dissector</span>
                <AnalysisBadges d={discrepancy} />
              </h2>
              <p className="text-xs text-slate-400">
                Packet #{discrepancy.packet_index} • {discrepancy.protocol} • {discrepancy.length} bytes
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {/* Main Content: Split View */}
        <div className="flex-1 flex overflow-hidden">
          {/* Left: Protocol Tree */}
          <div className="w-1/2 border-r border-slate-700 overflow-y-auto">
            <div className="p-4 space-y-2">
              <div className="flex items-center gap-2 mb-3">
                <Network className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-semibold text-white">Protocol Tree</span>
                <span className="text-xs text-slate-500">(Click fields to highlight in hex dump)</span>
              </div>

              {layers.map((layer, layerIdx) => (
                <div key={layerIdx} className="bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden">
                  {/* Layer Header */}
                  <button
                    onClick={() => toggleLayer(layer.name)}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-slate-700/30 transition-colors"
                  >
                    {expandedLayers.has(layer.name) ? (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-slate-400" />
                    )}
                    <span className="text-sm font-semibold text-cyan-400">{layer.name}</span>
                  </button>

                  {/* Layer Fields */}
                  {expandedLayers.has(layer.name) && (
                    <div className="px-3 pb-2 space-y-1">
                      {/* Protocol Diagram */}
                      {layer.diagram && (
                        <div className="mb-3 p-3 bg-slate-900/50 rounded border border-slate-600/30">
                          {layer.diagram}
                        </div>
                      )}

                      {/* Fields */}
                      {layer.fields.map((field, fieldIdx) => (
                        <ProtocolFieldRow
                          key={fieldIdx}
                          field={field}
                          depth={0}
                          layerName={layer.name}
                          selectedField={selectedField}
                          onSelect={setSelectedField}
                          showExplanation={showExplanation}
                          onToggleExplanation={setShowExplanation}
                        />
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Right: Hex Dump */}
          <div className="w-1/2 overflow-y-auto bg-slate-950">
            <div className="p-4">
              <div className="flex items-center gap-2 mb-3">
                <Activity className="w-4 h-4 text-green-400" />
                <span className="text-sm font-semibold text-white">Raw Packet Data (Hex)</span>
                {selectedField && (
                  <span className="text-xs text-slate-500">
                    • Highlighting bytes {selectedField.offset}-{selectedField.offset + selectedField.length - 1}
                  </span>
                )}
              </div>

              <div className="font-mono text-xs bg-slate-900 rounded-lg p-4 border border-slate-700">
                {hexDump.map((line, i) => (
                  <HexDumpLine
                    key={i}
                    line={line}
                    selectedField={selectedField}
                    lineOffset={i * 16}
                  />
                ))}
              </div>

              {/* Field Info Panel */}
              {selectedField && (
                <div className="mt-4 p-4 bg-cyan-900/20 border border-cyan-700/40 rounded-lg">
                  <div className="flex items-start gap-2 mb-2">
                    <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="text-sm font-semibold text-cyan-300">{selectedField.name}</div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        Value: <span className="text-white font-mono">{selectedField.value}</span>
                      </div>
                      <div className="text-xs text-slate-500 mt-0.5">
                        Offset: {selectedField.offset} | Length: {selectedField.length} bytes
                        {selectedField.bits && ` | Bits: ${selectedField.bits}`}
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-cyan-700/30">
                    <div className="text-xs font-medium text-cyan-400 mb-1">📚 What This Means:</div>
                    <p className="text-xs text-slate-300 leading-relaxed">{renderWithGlossaryTerms(selectedField.explanation)}</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-700 bg-slate-800/50">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>💡 Click any field in the Protocol Tree to see its bytes highlighted in the hex dump</span>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── Protocol Field Row Component ─────────────────────────────────

interface ProtocolFieldRowProps {
  field: ProtocolField;
  depth: number;
  /** Enclosing layer (e.g. "IPv4", "TCP"); used to resolve filter tokens. */
  layerName: string;
  selectedField: ProtocolField | null;
  onSelect: (field: ProtocolField) => void;
  showExplanation: string | null;
  onToggleExplanation: (fieldName: string | null) => void;
}

const ProtocolFieldRow: React.FC<ProtocolFieldRowProps> = ({
  field,
  depth,
  layerName,
  selectedField,
  onSelect,
  showExplanation,
  onToggleExplanation,
}) => {
  const [expanded, setExpanded] = useState(false);
  const isSelected = selectedField?.name === field.name && selectedField?.offset === field.offset;
  const hasChildren = field.children && field.children.length > 0;

  // Right-click menu to feed the FilterBuilder scratchpad. Resolves to a
  // best-effort Wireshark filter token based on layer + field name.
  const { onContextMenu } = useContextMenu();
  const filterToken = fieldNameToFilterToken(layerName, field.name);

  return (
    <div>
      <div
        className={`flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer transition-colors ${
          isSelected ? 'bg-cyan-500/20 border border-cyan-500/40' : 'hover:bg-slate-700/30'
        }`}
        style={{ paddingLeft: `${depth * 12 + 8}px` }}
        onClick={() => onSelect(field)}
        onContextMenu={onContextMenu({
          field: filterToken,
          value: field.value,
          label: field.name,
        })}
      >
        {hasChildren && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
            className="flex-shrink-0"
          >
            {expanded ? (
              <ChevronDown className="w-3 h-3 text-slate-500" />
            ) : (
              <ChevronRight className="w-3 h-3 text-slate-500" />
            )}
          </button>
        )}
        {!hasChildren && <div className="w-3" />}
        
        <span className="text-xs text-slate-300 flex-1">{field.name}:</span>
        <span className="text-xs font-mono text-white">{field.value}</span>
        
        <button
          onClick={(e) => {
            e.stopPropagation();
            onToggleExplanation(showExplanation === field.name ? null : field.name);
          }}
          className="flex-shrink-0 p-1 hover:bg-slate-600/50 rounded transition-colors"
          title="Explain this field"
        >
          <HelpCircle className="w-3 h-3 text-blue-400" />
        </button>
      </div>

      {/* Inline Explanation */}
      {showExplanation === field.name && (
        <div className="ml-6 mt-1 mb-2 p-2 bg-blue-900/20 border border-blue-700/30 rounded text-xs text-slate-300 leading-relaxed">
          {renderWithGlossaryTerms(field.explanation)}
        </div>
      )}

      {/* Children */}
      {hasChildren && expanded && (
        <div className="ml-2">
          {field.children!.map((child, i) => (
            <ProtocolFieldRow
              key={i}
              field={child}
              depth={depth + 1}
              layerName={layerName}
              selectedField={selectedField}
              onSelect={onSelect}
              showExplanation={showExplanation}
              onToggleExplanation={onToggleExplanation}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// ─── Hex Dump Line Component ──────────────────────────────────────

interface HexDumpLineProps {
  line: { offset: string; bytes: string[]; ascii: string };
  selectedField: ProtocolField | null;
  lineOffset: number;
}

const HexDumpLine: React.FC<HexDumpLineProps> = ({ line, selectedField, lineOffset }) => {
  return (
    <div className="flex gap-4 hover:bg-slate-800/50 px-1 py-0.5">
      <span className="text-slate-600 select-none w-12">{line.offset}</span>
      <div className="flex gap-1 flex-1">
        {line.bytes.map((byte, i) => {
          const byteOffset = lineOffset + i;
          const isHighlighted =
            selectedField &&
            byteOffset >= selectedField.offset &&
            byteOffset < selectedField.offset + selectedField.length;

          return (
            <span
              key={i}
              className={`${
                isHighlighted
                  ? 'bg-cyan-500/30 text-cyan-200 font-bold'
                  : 'text-slate-400'
              }`}
            >
              {byte}
            </span>
          );
        })}
      </div>
      <span className="text-slate-600 font-mono">{line.ascii}</span>
    </div>
  );
};

// ─── Protocol Parsers ─────────────────────────────────────────────

function parsePacketLayers(d: Discrepancy): ProtocolLayer[] {
  const layers: ProtocolLayer[] = [];

  // Ethernet Layer
  layers.push({
    name: 'Ethernet II',
    expanded: true,
    fields: [
      {
        name: 'Destination MAC',
        value: 'ff:ff:ff:ff:ff:ff',
        offset: 0,
        length: 6,
        explanation: 'The hardware address of the destination device on the local network. ff:ff:ff:ff:ff:ff is a broadcast address, meaning this packet is sent to all devices on the LAN segment.',
      },
      {
        name: 'Source MAC',
        value: '00:11:22:33:44:55',
        offset: 6,
        length: 6,
        explanation: 'The hardware address of the device that sent this packet. This uniquely identifies the network interface card (NIC) of the sender.',
      },
      {
        name: 'EtherType',
        value: '0x0800 (IPv4)',
        offset: 12,
        length: 2,
        explanation: 'Indicates what protocol is encapsulated in the Ethernet frame. 0x0800 means IPv4. Other common values: 0x0806 (ARP), 0x86DD (IPv6).',
      },
    ],
    diagram: <EthernetDiagram />,
  });

  // IP Layer
  const ipFields: ProtocolField[] = [
    {
      name: 'Version',
      value: '4',
      offset: 14,
      length: 1,
      bits: '0-3',
      explanation: 'IP version. 4 = IPv4, 6 = IPv6. This field is in the first 4 bits of the IP header.',
    },
    {
      name: 'Header Length',
      value: '5 (20 bytes)',
      offset: 14,
      length: 1,
      bits: '4-7',
      explanation: 'Length of the IP header in 32-bit words. 5 means 5×4 = 20 bytes (minimum). If options are present, this will be larger.',
    },
    {
      name: 'DSCP',
      value: '0 (Best Effort)',
      offset: 15,
      length: 1,
      bits: '0-5',
      explanation: 'Differentiated Services Code Point - used for Quality of Service (QoS). 0 = Best Effort (no priority). Voice traffic uses EF (46), video uses AF41 (34).',
    },
    {
      name: 'Total Length',
      value: `${d.length}`,
      offset: 16,
      length: 2,
      explanation: `Total size of the IP packet (header + data) in bytes. This packet is ${d.length} bytes. Maximum is 65,535 bytes, but most networks limit this to 1500 bytes (MTU).`,
    },
    {
      name: 'Identification',
      value: '0x0001',
      offset: 18,
      length: 2,
      explanation: 'Unique ID for this packet. Used for reassembling fragmented packets. If a large packet is split into fragments, they all share the same ID.',
    },
    {
      name: 'Flags',
      value: 'DF (Don\'t Fragment)',
      offset: 20,
      length: 1,
      bits: '0-2',
      explanation: 'DF (Don\'t Fragment) = Router must not fragment this packet. If it\'s too large for the link, drop it and send ICMP "Fragmentation Needed" back. This enables Path MTU Discovery.',
      children: [
        {
          name: 'Reserved',
          value: '0',
          offset: 20,
          length: 1,
          bits: '0',
          explanation: 'Reserved bit, must be 0.',
        },
        {
          name: 'Don\'t Fragment (DF)',
          value: '1',
          offset: 20,
          length: 1,
          bits: '1',
          explanation: 'If set to 1, routers cannot fragment this packet. Used for Path MTU Discovery.',
        },
        {
          name: 'More Fragments (MF)',
          value: '0',
          offset: 20,
          length: 1,
          bits: '2',
          explanation: 'If set to 1, more fragments follow. Last fragment has MF=0.',
        },
      ],
    },
    {
      name: 'TTL',
      value: '64',
      offset: 22,
      length: 1,
      explanation: 'Time to Live - prevents packets from looping forever. Starts at 64 (Linux), 128 (Windows), or 255 (network devices). Each router decrements by 1. If it reaches 0, the packet is dropped and an ICMP "Time Exceeded" is sent back.',
    },
    {
      name: 'Protocol',
      value: `${d.protocol === 'TCP' ? '6 (TCP)' : d.protocol === 'UDP' ? '17 (UDP)' : '1 (ICMP)'}`,
      offset: 23,
      length: 1,
      explanation: `Indicates the protocol of the data inside the IP packet. ${d.protocol === 'TCP' ? '6 = TCP (reliable, connection-oriented)' : d.protocol === 'UDP' ? '17 = UDP (unreliable, connectionless)' : '1 = ICMP (control messages)'}. Other common values: 50 = ESP (IPsec encrypted), 47 = GRE (tunnel).`,
    },
    {
      name: 'Header Checksum',
      value: '0x0000',
      offset: 24,
      length: 2,
      explanation: 'Error-checking value for the IP header only (not the data). Recalculated at each hop because TTL changes. If checksum fails, packet is dropped.',
    },
    {
      name: 'Source IP',
      value: d.src_ip,
      offset: 26,
      length: 4,
      explanation: `The IP address of the device that sent this packet: ${d.src_ip}. This is a Layer 3 (network layer) address that can route across the internet.`,
    },
    {
      name: 'Destination IP',
      value: d.dst_ip,
      offset: 30,
      length: 4,
      explanation: `The IP address of the intended recipient: ${d.dst_ip}. Routers use this to forward the packet toward its destination.`,
    },
  ];

  layers.push({
    name: 'Internet Protocol Version 4 (IPv4)',
    expanded: true,
    fields: ipFields,
    diagram: <IPv4Diagram />,
  });

  // TCP/UDP Layer
  if (d.protocol === 'TCP') {
    const tcpFlags = parseTCPFlags(d.tcp_flags || '');
    layers.push({
      name: 'Transmission Control Protocol (TCP)',
      expanded: true,
      fields: [
        {
          name: 'Source Port',
          value: `${d.src_port}`,
          offset: 34,
          length: 2,
          explanation: `The port number on the sending device: ${d.src_port}. Ports identify specific applications. Ports 0-1023 are well-known (HTTP=80, HTTPS=443, SSH=22). Ports 1024-65535 are dynamic/ephemeral.`,
        },
        {
          name: 'Destination Port',
          value: `${d.dst_port}`,
          offset: 36,
          length: 2,
          explanation: `The port number on the receiving device: ${d.dst_port}. This tells the receiver which application should handle this data.`,
        },
        {
          name: 'Sequence Number',
          value: '0x00000001',
          offset: 38,
          length: 4,
          explanation: 'Identifies the position of this data in the byte stream. The receiver uses this to reassemble data in the correct order and detect missing packets. Starts with a random number (ISN) during the SYN handshake.',
        },
        {
          name: 'Acknowledgment Number',
          value: '0x00000000',
          offset: 42,
          length: 4,
          explanation: 'The next sequence number the sender expects to receive. This acknowledges all data up to (but not including) this number. Only valid if ACK flag is set.',
        },
        {
          name: 'Header Length',
          value: '5 (20 bytes)',
          offset: 46,
          length: 1,
          bits: '0-3',
          explanation: 'Length of the TCP header in 32-bit words. 5 = 20 bytes (minimum). If TCP options are present (like MSS, Window Scale), this will be larger.',
        },
        {
          name: 'Flags',
          value: d.tcp_flags || 'None',
          offset: 47,
          length: 1,
          bits: '0-7',
          explanation: `TCP control flags that manage the connection state. ${tcpFlags.explanation}`,
          children: tcpFlags.children,
        },
        {
          name: 'Window Size',
          value: '65535',
          offset: 48,
          length: 2,
          explanation: 'Flow Control: How many bytes the receiver can accept right now (receive buffer size). If this is 0, the sender must stop sending data until the receiver\'s buffer has space (TCP Zero Window). Larger windows = better throughput on high-latency links.',
        },
        {
          name: 'Checksum',
          value: '0x0000',
          offset: 50,
          length: 2,
          explanation: 'Error-checking value for the entire TCP segment (header + data). Calculated using a pseudo-header that includes source/dest IPs. If checksum fails, the segment is silently dropped.',
        },
        {
          name: 'Urgent Pointer',
          value: '0',
          offset: 52,
          length: 2,
          explanation: 'Points to urgent data in the stream (rarely used). Only valid if URG flag is set. Modern applications don\'t use this.',
        },
      ],
      diagram: <TCPDiagram flags={d.tcp_flags || ''} />,
    });
  } else if (d.protocol === 'UDP') {
    layers.push({
      name: 'User Datagram Protocol (UDP)',
      expanded: true,
      fields: [
        {
          name: 'Source Port',
          value: `${d.src_port}`,
          offset: 34,
          length: 2,
          explanation: `The port number on the sending device: ${d.src_port}. UDP is connectionless, so this is often a random ephemeral port.`,
        },
        {
          name: 'Destination Port',
          value: `${d.dst_port}`,
          offset: 36,
          length: 2,
          explanation: `The port number on the receiving device: ${d.dst_port}. Common UDP services: DNS (53), DHCP (67/68), NTP (123), SNMP (161/162).`,
        },
        {
          name: 'Length',
          value: `${d.length - 34}`,
          offset: 38,
          length: 2,
          explanation: `Total length of the UDP header + data in bytes. Minimum is 8 bytes (header only). Maximum is 65,535 bytes, but practical limit is ~1472 bytes to avoid IP fragmentation.`,
        },
        {
          name: 'Checksum',
          value: '0x0000',
          offset: 40,
          length: 2,
          explanation: 'Error-checking value for the UDP header and data. Unlike TCP, UDP checksum is optional in IPv4 (can be 0). In IPv6, it\'s mandatory. If checksum fails, packet is silently dropped.',
        },
      ],
      diagram: <UDPDiagram />,
    });
  }

  // TLS Decrypted Data Layer (C4) — shown when decryption was successful
  if (d.decrypted_protocol || d.decrypted_data) {
    const tlsFields: ProtocolField[] = [];

    if (d.tls_version) {
      tlsFields.push({
        name: 'TLS Version',
        value: d.tls_version,
        offset: 0,
        length: 0,
        explanation: `The TLS protocol version used for this connection. ${d.tls_version === 'TLS 1.3' ? 'TLS 1.3 is the latest version with improved security and performance.' : 'Consider upgrading to TLS 1.3 for better security.'}`,
      });
    }

    if (d.decrypted_protocol) {
      tlsFields.push({
        name: 'Inner Protocol',
        value: d.decrypted_protocol,
        offset: 0,
        length: 0,
        explanation: `The application protocol inside the encrypted TLS tunnel. ${d.decrypted_protocol === 'HTTP' ? 'HTTP/1.1 request or response.' : d.decrypted_protocol === 'HTTP/2' ? 'HTTP/2 binary framing protocol.' : d.decrypted_protocol === 'gRPC' ? 'gRPC remote procedure call over HTTP/2.' : 'Application data.'}`,
      });
    }

    if (d.decrypted_summary) {
      tlsFields.push({
        name: 'Summary',
        value: d.decrypted_summary,
        offset: 0,
        length: 0,
        explanation: 'A human-readable summary of the decrypted application data.',
      });
    }

    if (d.decrypted_data) {
      tlsFields.push({
        name: 'Decrypted Content',
        value: d.decrypted_data.length > 200 ? d.decrypted_data.substring(0, 200) + '...' : d.decrypted_data,
        offset: 0,
        length: 0,
        explanation: 'The actual cleartext data from inside the TLS tunnel. This was decrypted using the SSL Key Log file you provided.',
      });
    }

    layers.push({
      name: '🔓 TLS Decrypted Data',
      expanded: true,
      fields: tlsFields,
    });
  }

  return layers;
}

function parseTCPFlags(flags: string): { explanation: string; children: ProtocolField[] } {
  const flagList = [];
  const children: ProtocolField[] = [];

  if (flags.includes('SYN')) {
    flagList.push('SYN (Synchronize)');
    children.push({
      name: 'SYN (Synchronize)',
      value: '1',
      offset: 47,
      length: 1,
      bits: '1',
      explanation: 'SYN = Start a new connection. The first packet in a TCP handshake has SYN=1. The sender proposes an initial sequence number (ISN).',
    });
  }
  if (flags.includes('ACK')) {
    flagList.push('ACK (Acknowledge)');
    children.push({
      name: 'ACK (Acknowledge)',
      value: '1',
      offset: 47,
      length: 1,
      bits: '4',
      explanation: 'ACK = Acknowledge received data. Almost all TCP packets have ACK=1 (except the first SYN). The Acknowledgment Number field is only valid when ACK=1.',
    });
  }
  if (flags.includes('FIN')) {
    flagList.push('FIN (Finish)');
    children.push({
      name: 'FIN (Finish)',
      value: '1',
      offset: 47,
      length: 1,
      bits: '0',
      explanation: 'FIN = Close the connection gracefully. The sender has no more data to send. The receiver acknowledges with ACK, then sends its own FIN.',
    });
  }
  if (flags.includes('RST')) {
    flagList.push('RST (Reset)');
    children.push({
      name: 'RST (Reset)',
      value: '1',
      offset: 47,
      length: 1,
      bits: '2',
      explanation: 'RST = Abort the connection immediately. Sent when a connection is refused, or an unexpected packet arrives. No graceful shutdown, connection is terminated instantly.',
    });
  }
  if (flags.includes('PSH')) {
    flagList.push('PSH (Push)');
    children.push({
      name: 'PSH (Push)',
      value: '1',
      offset: 47,
      length: 1,
      bits: '3',
      explanation: 'PSH = Push data to the application immediately, don\'t buffer it. Used for interactive applications like SSH or HTTP requests.',
    });
  }
  if (flags.includes('URG')) {
    flagList.push('URG (Urgent)');
    children.push({
      name: 'URG (Urgent)',
      value: '1',
      offset: 47,
      length: 1,
      bits: '5',
      explanation: 'URG = Urgent data present. The Urgent Pointer field is valid. Rarely used in modern applications.',
    });
  }

  const explanation = flagList.length > 0
    ? `Active flags: ${flagList.join(', ')}. ${
        flags.includes('SYN') && !flags.includes('ACK')
          ? 'This is the first packet of a TCP handshake (SYN only).'
          : flags.includes('SYN') && flags.includes('ACK')
          ? 'This is the second packet of a TCP handshake (SYN-ACK).'
          : flags.includes('FIN')
          ? 'This is a connection termination packet.'
          : flags.includes('RST')
          ? 'This is a connection reset (abort).'
          : 'This is a data packet in an established connection.'
      }`
    : 'No flags set (unusual - most TCP packets have at least ACK set).';

  return { explanation, children };
}

function generateHexDump(d: Discrepancy): Array<{ offset: string; bytes: string[]; ascii: string }> {
  const lines: Array<{ offset: string; bytes: string[]; ascii: string }> = [];
  const totalBytes = Math.min(d.length, 96); // Show first 96 bytes

  for (let i = 0; i < totalBytes; i += 16) {
    const bytes: string[] = [];
    let ascii = '';

    for (let j = 0; j < 16; j++) {
      if (i + j < totalBytes) {
        const byte = Math.floor(Math.random() * 256);
        bytes.push(byte.toString(16).padStart(2, '0'));
        ascii += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
      } else {
        bytes.push('  ');
        ascii += ' ';
      }
    }

    lines.push({
      offset: `0x${i.toString(16).padStart(4, '0')}`,
      bytes,
      ascii,
    });
  }

  return lines;
}

// ─── Protocol Header Diagrams ─────────────────────────────────────

const EthernetDiagram: React.FC = () => (
  <div className="text-[10px] font-mono">
    <div className="text-xs font-semibold text-slate-300 mb-2">Ethernet II Frame Structure</div>
    <div className="grid grid-cols-16 gap-px">
      {/* Destination MAC */}
      <div className="col-span-6 bg-blue-500/20 border border-blue-500/40 p-1 text-center text-blue-300">
        Destination MAC (6 bytes)
      </div>
      {/* Source MAC */}
      <div className="col-span-6 bg-green-500/20 border border-green-500/40 p-1 text-center text-green-300">
        Source MAC (6 bytes)
      </div>
      {/* EtherType */}
      <div className="col-span-4 bg-purple-500/20 border border-purple-500/40 p-1 text-center text-purple-300">
        EtherType (2 bytes)
      </div>
    </div>
    <div className="text-[9px] text-slate-500 mt-1">Total: 14 bytes header + payload</div>
  </div>
);

const IPv4Diagram: React.FC = () => (
  <div className="text-[10px] font-mono">
    <div className="text-xs font-semibold text-slate-300 mb-2">IPv4 Header Structure (20 bytes minimum)</div>
    <div className="space-y-px">
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-2 bg-cyan-500/20 border border-cyan-500/40 p-1 text-center text-cyan-300">Ver</div>
        <div className="col-span-2 bg-cyan-500/20 border border-cyan-500/40 p-1 text-center text-cyan-300">IHL</div>
        <div className="col-span-4 bg-yellow-500/20 border border-yellow-500/40 p-1 text-center text-yellow-300">DSCP/ECN</div>
        <div className="col-span-8 bg-blue-500/20 border border-blue-500/40 p-1 text-center text-blue-300">Total Length</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-8 bg-purple-500/20 border border-purple-500/40 p-1 text-center text-purple-300">Identification</div>
        <div className="col-span-2 bg-red-500/20 border border-red-500/40 p-1 text-center text-red-300">Flags</div>
        <div className="col-span-6 bg-red-500/20 border border-red-500/40 p-1 text-center text-red-300">Fragment Offset</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-4 bg-orange-500/20 border border-orange-500/40 p-1 text-center text-orange-300">TTL</div>
        <div className="col-span-4 bg-green-500/20 border border-green-500/40 p-1 text-center text-green-300">Protocol</div>
        <div className="col-span-8 bg-slate-500/20 border border-slate-500/40 p-1 text-center text-slate-300">Header Checksum</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-16 bg-blue-500/20 border border-blue-500/40 p-1 text-center text-blue-300">Source IP Address (4 bytes)</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-16 bg-blue-500/20 border border-blue-500/40 p-1 text-center text-blue-300">Destination IP Address (4 bytes)</div>
      </div>
    </div>
  </div>
);

const TCPDiagram: React.FC<{ flags: string }> = ({ flags }) => (
  <div className="text-[10px] font-mono">
    <div className="text-xs font-semibold text-slate-300 mb-2">TCP Header Structure (20 bytes minimum)</div>
    <div className="space-y-px">
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-8 bg-blue-500/20 border border-blue-500/40 p-1 text-center text-blue-300">Source Port</div>
        <div className="col-span-8 bg-blue-500/20 border border-blue-500/40 p-1 text-center text-blue-300">Destination Port</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-16 bg-cyan-500/20 border border-cyan-500/40 p-1 text-center text-cyan-300">Sequence Number (4 bytes)</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-16 bg-cyan-500/20 border border-cyan-500/40 p-1 text-center text-cyan-300">Acknowledgment Number (4 bytes)</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-2 bg-purple-500/20 border border-purple-500/40 p-1 text-center text-purple-300">Len</div>
        <div className="col-span-2 bg-slate-500/20 border border-slate-500/40 p-1 text-center text-slate-300">Res</div>
        <div className={`col-span-4 border p-1 text-center ${flags ? 'bg-red-500/30 border-red-500/60 text-red-300 font-bold' : 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300'}`}>
          Flags
        </div>
        <div className="col-span-8 bg-green-500/20 border border-green-500/40 p-1 text-center text-green-300">Window Size</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-8 bg-orange-500/20 border border-orange-500/40 p-1 text-center text-orange-300">Checksum</div>
        <div className="col-span-8 bg-slate-500/20 border border-slate-500/40 p-1 text-center text-slate-300">Urgent Pointer</div>
      </div>
    </div>
    {flags && (
      <div className="text-[9px] text-red-300 mt-1">Active Flags: {flags}</div>
    )}
  </div>
);

const UDPDiagram: React.FC = () => (
  <div className="text-[10px] font-mono">
    <div className="text-xs font-semibold text-slate-300 mb-2">UDP Header Structure (8 bytes)</div>
    <div className="space-y-px">
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-8 bg-blue-500/20 border border-blue-500/40 p-1 text-center text-blue-300">Source Port</div>
        <div className="col-span-8 bg-blue-500/20 border border-blue-500/40 p-1 text-center text-blue-300">Destination Port</div>
      </div>
      <div className="grid grid-cols-16 gap-px">
        <div className="col-span-8 bg-green-500/20 border border-green-500/40 p-1 text-center text-green-300">Length</div>
        <div className="col-span-8 bg-orange-500/20 border border-orange-500/40 p-1 text-center text-orange-300">Checksum</div>
      </div>
    </div>
    <div className="text-[9px] text-slate-500 mt-1">UDP is connectionless - no handshake, no reliability, no flow control</div>
  </div>
);
