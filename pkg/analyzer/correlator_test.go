package analyzer

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func TestCorrelator_BGPWithdrawalRetransmissionSpike(t *testing.T) {
	c := NewUnderlayOverlayCorrelator()
	report := &models.TriageReport{}

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// Record a BGP withdrawal
	c.RecordBGPEvent(base, "10.0.0.1", "192.168.0.0/16", "Withdrawal",
		"Peer 10.0.0.1: BGP Withdrawal (withdrawn_len=4)")

	// Record retransmissions within the 5-second window
	for i := 0; i < 8; i++ {
		ts := base.Add(time.Duration(i*500) * time.Millisecond)
		flowKey := "10.1.1.1:443->10.2.2.2:50000"
		c.RecordRetransmission(ts, flowKey, "10.1.1.1", "10.2.2.2")
	}

	c.Finalize(report)

	if len(report.RootCauseChains) == 0 {
		t.Fatal("expected at least one RootCauseChain entry")
	}

	chain := report.RootCauseChains[0]
	if chain.UnderlayEvent != "BGP Withdrawal" {
		t.Errorf("UnderlayEvent = %q, want %q", chain.UnderlayEvent, "BGP Withdrawal")
	}
	if chain.OverlayEffect != "TCP Retransmission Spike" {
		t.Errorf("OverlayEffect = %q, want %q", chain.OverlayEffect, "TCP Retransmission Spike")
	}
	if chain.CorrelationGap < 0 || chain.CorrelationGap > 5.0 {
		t.Errorf("CorrelationGap = %.2f, want between 0 and 5", chain.CorrelationGap)
	}
	if chain.Recommendation == "" {
		t.Error("expected non-empty Recommendation")
	}
}

func TestCorrelator_BGPNotificationRTTSpike(t *testing.T) {
	c := NewUnderlayOverlayCorrelator()
	report := &models.TriageReport{}

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// Record a BGP notification (session reset)
	c.RecordBGPEvent(base, "10.0.0.1", "10.0.0.2", "Notification",
		"BGP NOTIFICATION: Error 6/4 from 10.0.0.1")

	// Record RTT spikes within the 5-second window
	c.RecordRTTSpike(base.Add(1*time.Second), "10.1.1.1:80->10.2.2.2:50000", "10.1.1.1", "10.2.2.2", 350.0)
	c.RecordRTTSpike(base.Add(2*time.Second), "10.1.1.1:80->10.2.2.2:50001", "10.1.1.1", "10.2.2.2", 500.0)

	c.Finalize(report)

	if len(report.RootCauseChains) == 0 {
		t.Fatal("expected at least one RootCauseChain entry for RTT spike")
	}

	chain := report.RootCauseChains[0]
	if chain.OverlayEffect != "RTT Spike" {
		t.Errorf("OverlayEffect = %q, want %q", chain.OverlayEffect, "RTT Spike")
	}
	if chain.Severity != "High" && chain.Severity != "Critical" {
		t.Errorf("Severity = %q, want High or Critical for 500ms RTT", chain.Severity)
	}
}

func TestCorrelator_NoCorrelationOutsideWindow(t *testing.T) {
	c := NewUnderlayOverlayCorrelator()
	report := &models.TriageReport{}

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// BGP event at T=0
	c.RecordBGPEvent(base, "10.0.0.1", "192.168.0.0/16", "Withdrawal", "test")

	// Retransmissions at T=10s (outside 5s window)
	for i := 0; i < 10; i++ {
		ts := base.Add(10*time.Second + time.Duration(i*100)*time.Millisecond)
		c.RecordRetransmission(ts, "flow1", "10.1.1.1", "10.2.2.2")
	}

	c.Finalize(report)

	if len(report.RootCauseChains) != 0 {
		t.Errorf("expected 0 RootCauseChains for events outside window, got %d", len(report.RootCauseChains))
	}
}

func TestCorrelator_NoBGPEvents(t *testing.T) {
	c := NewUnderlayOverlayCorrelator()
	report := &models.TriageReport{}

	// Only overlay events, no BGP
	c.RecordRetransmission(time.Now(), "flow1", "10.1.1.1", "10.2.2.2")
	c.RecordRTTSpike(time.Now(), "flow1", "10.1.1.1", "10.2.2.2", 500.0)

	c.Finalize(report)

	if len(report.RootCauseChains) != 0 {
		t.Errorf("expected 0 RootCauseChains without BGP events, got %d", len(report.RootCauseChains))
	}
}

func TestCorrelator_BelowRetransmitThreshold(t *testing.T) {
	c := NewUnderlayOverlayCorrelator()
	report := &models.TriageReport{}

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	c.RecordBGPEvent(base, "10.0.0.1", "192.168.0.0/16", "Update", "test")

	// Only 2 retransmissions (below default threshold of 3)
	c.RecordRetransmission(base.Add(1*time.Second), "flow1", "10.1.1.1", "10.2.2.2")
	c.RecordRetransmission(base.Add(2*time.Second), "flow1", "10.1.1.1", "10.2.2.2")

	c.Finalize(report)

	// Should have 0 retransmission chains (below threshold) but could have RTT chains
	for _, chain := range report.RootCauseChains {
		if chain.OverlayEffect == "TCP Retransmission Spike" {
			t.Error("should not produce retransmission chain below threshold")
		}
	}
}

func TestCorrelator_Stats(t *testing.T) {
	c := NewUnderlayOverlayCorrelator()

	c.RecordBGPEvent(time.Now(), "10.0.0.1", "10.0.0.2", "Update", "test")
	c.RecordBGPEvent(time.Now(), "10.0.0.1", "10.0.0.2", "Withdrawal", "test")
	c.RecordRetransmission(time.Now(), "flow1", "10.1.1.1", "10.2.2.2")
	c.RecordRTTSpike(time.Now(), "flow1", "10.1.1.1", "10.2.2.2", 300.0)

	bgp, retrans, rtt := c.Stats()
	if bgp != 2 {
		t.Errorf("bgpCount = %d, want 2", bgp)
	}
	if retrans != 1 {
		t.Errorf("retransCount = %d, want 1", retrans)
	}
	if rtt != 1 {
		t.Errorf("rttSpikeCount = %d, want 1", rtt)
	}
}
