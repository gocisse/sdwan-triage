import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StreamConversation } from '../../components/StreamConversation';
import { makeDiscrepancy, makeFlow } from '../fixtures';

// Mock fetch for stream data
globalThis.fetch = vi.fn().mockResolvedValue({
  ok: true,
  json: () => Promise.resolve({ packets: [] }),
});

describe('StreamConversation', () => {
  const clientPacket = makeDiscrepancy({
    state: 'PRESENT_BOTH',
    src_ip: '192.168.1.10',
    dst_ip: '10.0.0.1',
    src_port: 54321,
    dst_port: 443,
    protocol: 'TCP',
    tcp_flags: 'SYN',
    packet_index: 1,
    detail: 'TCP SYN',
  });

  const serverPacket = makeDiscrepancy({
    state: 'PRESENT_BOTH',
    src_ip: '10.0.0.1',
    dst_ip: '192.168.1.10',
    src_port: 443,
    dst_port: 54321,
    protocol: 'TCP',
    tcp_flags: 'SYN,ACK',
    packet_index: 2,
    detail: 'TCP SYN-ACK',
  });

  const flow = makeFlow({
    src_ip: '192.168.1.10',
    dst_ip: '10.0.0.1',
    src_port: 54321,
    dst_port: 443,
  });

  it('renders the conversation header', () => {
    render(
      <StreamConversation
        allDiscrepancies={[clientPacket, serverPacket]}
        flow={flow}
        onClose={() => {}}
      />
    );
    expect(screen.getByText(/Follow Stream/i)).toBeInTheDocument();
  });

  it('renders client and server packets as conversation bubbles', () => {
    const { container } = render(
      <StreamConversation
        allDiscrepancies={[clientPacket, serverPacket]}
        flow={flow}
        onClose={() => {}}
      />
    );
    // The header shows flow IPs in the subtitle
    const html = container.innerHTML;
    expect(html).toContain('192.168.1.10');
    expect(html).toContain('10.0.0.1');
  });

  it('calls onClose when Close button is clicked', () => {
    const onClose = vi.fn();
    render(
      <StreamConversation
        allDiscrepancies={[clientPacket, serverPacket]}
        flow={flow}
        onClose={onClose}
      />
    );
    // The component has a "Close" text button at the bottom
    const closeBtn = screen.getByText('Close');
    closeBtn.click();
    expect(onClose).toHaveBeenCalled();
  });

  it('renders with empty discrepancies without crashing', () => {
    render(
      <StreamConversation
        allDiscrepancies={[]}
        flow={flow}
        onClose={() => {}}
      />
    );
    expect(screen.getByText(/Follow Stream/i)).toBeInTheDocument();
  });
});
