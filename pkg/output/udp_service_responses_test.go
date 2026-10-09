package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func udpText(r *models.TriageReport) string {
	var b bytes.Buffer
	WriteUDPServiceResponses(&b, r)
	return b.String()
}

func TestUDPServicesCLI_NothingWhenEverythingWasAnswered(t *testing.T) {
	if udpText(&models.TriageReport{}) != "" {
		t.Error("output without summary")
	}
	u := &models.UDPServiceResponses{MaxGroups: 50, Groups: []models.UDPServiceGroup{{Service: "SNMP", Conversations: 2, Requests: 4, Replies: 4}}}
	if udpText(&models.TriageReport{UDPServiceResponses: u}) != "" {
		t.Error("output although every conversation had a reply")
	}
}

func TestUDPServicesCLI_ListsOnlyUnansweredGroupsWithFramesAndLimits(t *testing.T) {
	u := &models.UDPServiceResponses{MaxGroups: 50, DatagramsUntracked: 7,
		Services: []models.UDPServiceTotals{{Service: "RADIUS", Conversations: 3, ConversationsWithoutReply: 3}, {Service: "SNMP", Conversations: 20, ConversationsWithoutReply: 9}},
		Groups: []models.UDPServiceGroup{
			{Service: "SNMP", Client: "10.0.0.1", Server: "10.0.0.2", ServerPort: 161, Conversations: 7, Requests: 47, ConversationsWithoutReply: 7, WithoutReplyNearCaptureEnd: 1, FirstUnansweredFrame: 298},
			{Service: "SNMP", Client: "10.0.0.1", Server: "10.0.0.3", ServerPort: 161, Conversations: 2, Requests: 13, Replies: 9, ConversationsWithoutReply: 1, FirstUnansweredFrame: 4716},
			{Service: "SNMP", Client: "10.0.0.1", Server: "10.0.0.4", ServerPort: 161, Conversations: 1, Requests: 3, Replies: 3},
		}}
	out := udpText(&models.TriageReport{UDPServiceResponses: u})
	for _, must := range []string{
		"UDP SERVICES (requests and replies observed in this capture; a missing reply does not show that the server failed or that packets were lost):",
		"RADIUS: 3 conversation(s), 3 with no reply observed.", "SNMP: 20 conversation(s), 9 with no reply observed.",
		"SNMP 10.0.0.1 -> 10.0.0.2:161: 7 conversation(s), 47 request(s), 0 reply(ies) observed; no reply in 7 conversation(s) (1 within 2 s of the end of the capture) (first unanswered request: frame 298).",
		"No reply from this server was observed at all",
		"SNMP 10.0.0.1 -> 10.0.0.3:161: 2 conversation(s), 13 request(s), 9 reply(ies) observed; no reply in 1 conversation(s) (first unanswered request: frame 4716).",
		"7 datagram(s) of conversations beyond the tracking bound", "Replies are not matched to individual requests",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("missing %q in:\n%s", must, out)
		}
	}
	if strings.Contains(out, "10.0.0.4") {
		t.Error("an answered group is listed")
	}
	if strings.Count(out, "No reply from this server was observed at all") != 1 {
		t.Error("the zero-reply note must appear only for groups without any reply")
	}
}

func TestUDPServicesCLI_DisplayBound(t *testing.T) {
	u := &models.UDPServiceResponses{MaxGroups: 50}
	for i := 0; i < 12; i++ {
		u.Groups = append(u.Groups, models.UDPServiceGroup{Service: "SNMP", Client: "c", Server: "s", ServerPort: 161, Conversations: 1, Requests: 1, ConversationsWithoutReply: 1})
	}
	out := udpText(&models.TriageReport{UDPServiceResponses: u})
	if strings.Count(out, "  SNMP c -> s:161") != cliUDPServiceMaxGroups {
		t.Errorf("groups shown:\n%s", out)
	}
	if !strings.Contains(out, "Display limited: showing 8 of 12 groups with unanswered conversations; the JSON list (udp_service_responses) is bounded at 50") {
		t.Errorf("notice missing:\n%s", out)
	}
}
