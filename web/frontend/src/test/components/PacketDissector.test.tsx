import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { PacketDissector } from '../../components/PacketDissector';
import { makeDiscrepancy } from '../fixtures';

// Mock the GlobalContextMenu hook
vi.mock('../../components/GlobalContextMenu', () => ({
  useContextMenu: () => ({
    onContextMenu: () => () => {},
  }),
}));

// Mock the Glossary (GlossaryTerm requires GlossaryProvider)
vi.mock('../../components/Glossary', () => ({
  GLOSSARY: {},
  GlossaryTerm: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
}));

// Mock AnalysisBadges
vi.mock('../../components/AnalysisBadges', () => ({
  AnalysisBadges: () => null,
}));

describe('PacketDissector', () => {
  const discrepancy = makeDiscrepancy({
    protocol: 'TCP',
    src_ip: '192.168.1.10',
    dst_ip: '10.0.0.1',
    src_port: 54321,
    dst_port: 443,
    length: 128,
    packet_index: 42,
    tcp_flags: 'SYN',
  });

  it('renders header with packet info', () => {
    render(<PacketDissector discrepancy={discrepancy} onClose={() => {}} />);
    expect(screen.getByText(/Interactive Packet Dissector/i)).toBeInTheDocument();
    expect(screen.getByText(/Packet #42/)).toBeInTheDocument();
    expect(screen.getByText(/128 bytes/)).toBeInTheDocument();
  });

  it('renders protocol layers (Ethernet II, IPv4, TCP)', () => {
    const { container } = render(<PacketDissector discrepancy={discrepancy} onClose={() => {}} />);
    const layerNames = container.querySelectorAll('.text-cyan-400');
    const names = Array.from(layerNames).map(el => el.textContent);
    expect(names).toContain('Ethernet II');
    expect(names).toContain('Internet Protocol Version 4 (IPv4)');
    expect(names).toContain('Transmission Control Protocol (TCP)');
  });

  it('renders fields when layer is manually expanded', () => {
    const { container } = render(<PacketDissector discrepancy={discrepancy} onClose={() => {}} />);
    // Layers start collapsed (expandedLayers set doesn't match full names)
    // Click the IPv4 layer button to expand it
    const buttons = container.querySelectorAll('button');
    const ipv4Btn = Array.from(buttons).find(b => b.textContent?.includes('IPv4'));
    expect(ipv4Btn).toBeDefined();
    fireEvent.click(ipv4Btn!);
    // Now IP fields should be visible
    const html = container.innerHTML;
    expect(html).toContain('Source IP');
    expect(html).toContain('Destination IP');
  });

  it('calls onClose when close button is clicked', () => {
    const onClose = vi.fn();
    render(<PacketDissector discrepancy={discrepancy} onClose={onClose} />);
    // Find the close button (X icon)
    const closeButtons = screen.getAllByRole('button');
    const closeBtn = closeButtons.find(btn => btn.querySelector('svg'));
    if (closeBtn) {
      fireEvent.click(closeBtn);
    }
    expect(onClose).toHaveBeenCalled();
  });

  it('can toggle layer expansion on and off', () => {
    const { container } = render(<PacketDissector discrepancy={discrepancy} onClose={() => {}} />);
    const buttons = container.querySelectorAll('button');
    const ipv4Btn = Array.from(buttons).find(b => b.textContent?.includes('IPv4'));
    expect(ipv4Btn).toBeDefined();
    // Click to expand
    fireEvent.click(ipv4Btn!);
    expect(container.innerHTML).toContain('Source IP');
    // Click to collapse
    fireEvent.click(ipv4Btn!);
    expect(container.innerHTML).not.toContain('Source IP');
  });
});
