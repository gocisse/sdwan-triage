package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TicketingSystem represents a ticketing system integration
type TicketingSystem interface {
	CreateTicket(ticket *Ticket) (*TicketResponse, error)
	UpdateTicket(ticketID string, update *TicketUpdate) error
	AddComment(ticketID string, comment string) error
	AttachFile(ticketID string, filename string, content []byte) error
	GetTicket(ticketID string) (*Ticket, error)
}

// Ticket represents a support ticket
type Ticket struct {
	ID              string         `json:"id,omitempty"`
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	Priority        TicketPriority `json:"priority"`
	Severity        TicketSeverity `json:"severity"`
	Category        string         `json:"category"`
	Subcategory     string         `json:"subcategory,omitempty"`
	AssignmentGroup string         `json:"assignment_group,omitempty"`
	Assignee        string         `json:"assignee,omitempty"`
	CustomerID      string         `json:"customer_id,omitempty"`
	CustomerName    string         `json:"customer_name,omitempty"`

	// SD-WAN specific fields
	SDWANVendor  string `json:"sdwan_vendor,omitempty"`
	AffectedSite string `json:"affected_site,omitempty"`
	IssueType    string `json:"issue_type,omitempty"`

	// Technical details
	WiresharkFilter string `json:"wireshark_filter,omitempty"`
	PcapFilename    string `json:"pcap_filename,omitempty"`
	DiagnosticData  string `json:"diagnostic_data,omitempty"`

	// Remediation
	SuggestedFix     string   `json:"suggested_fix,omitempty"`
	RemediationSteps []string `json:"remediation_steps,omitempty"`

	// Metadata
	CreatedAt    time.Time         `json:"created_at,omitempty"`
	UpdatedAt    time.Time         `json:"updated_at,omitempty"`
	Status       TicketStatus      `json:"status,omitempty"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
}

// TicketPriority represents ticket priority levels
type TicketPriority string

const (
	PriorityCritical TicketPriority = "1 - Critical"
	PriorityHigh     TicketPriority = "2 - High"
	PriorityMedium   TicketPriority = "3 - Medium"
	PriorityLow      TicketPriority = "4 - Low"
)

// TicketSeverity represents ticket severity levels
type TicketSeverity string

const (
	SeveritySev1 TicketSeverity = "1 - Critical"
	SeveritySev2 TicketSeverity = "2 - High"
	SeveritySev3 TicketSeverity = "3 - Medium"
	SeveritySev4 TicketSeverity = "4 - Low"
)

// TicketStatus represents ticket status
type TicketStatus string

const (
	StatusNew        TicketStatus = "New"
	StatusInProgress TicketStatus = "In Progress"
	StatusPending    TicketStatus = "Pending"
	StatusResolved   TicketStatus = "Resolved"
	StatusClosed     TicketStatus = "Closed"
)

// TicketResponse contains the response from ticket creation
type TicketResponse struct {
	TicketID  string    `json:"ticket_id"`
	TicketURL string    `json:"ticket_url"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

// TicketUpdate contains fields to update on a ticket
type TicketUpdate struct {
	Status          *TicketStatus   `json:"status,omitempty"`
	Priority        *TicketPriority `json:"priority,omitempty"`
	AssignmentGroup *string         `json:"assignment_group,omitempty"`
	Assignee        *string         `json:"assignee,omitempty"`
	Resolution      *string         `json:"resolution,omitempty"`
	WorkNotes       *string         `json:"work_notes,omitempty"`
}

// ServiceNowClient implements TicketingSystem for ServiceNow
type ServiceNowClient struct {
	BaseURL    string
	Username   string
	Password   string
	HTTPClient *http.Client
}

// NewServiceNowClient creates a new ServiceNow client
func NewServiceNowClient(baseURL, username, password string) *ServiceNowClient {
	return &ServiceNowClient{
		BaseURL:  strings.TrimSuffix(baseURL, "/"),
		Username: username,
		Password: password,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateTicket creates a new incident in ServiceNow
func (c *ServiceNowClient) CreateTicket(ticket *Ticket) (*TicketResponse, error) {
	// Map to ServiceNow incident format
	snowTicket := map[string]interface{}{
		"short_description": ticket.Title,
		"description":       ticket.Description,
		"urgency":           mapPriorityToUrgency(ticket.Priority),
		"impact":            mapSeverityToImpact(ticket.Severity),
		"category":          ticket.Category,
		"subcategory":       ticket.Subcategory,
		"assignment_group":  ticket.AssignmentGroup,
		"caller_id":         ticket.CustomerID,
	}

	// Add custom fields
	if ticket.WiresharkFilter != "" {
		snowTicket["u_wireshark_filter"] = ticket.WiresharkFilter
	}
	if ticket.SDWANVendor != "" {
		snowTicket["u_sdwan_vendor"] = ticket.SDWANVendor
	}
	if ticket.SuggestedFix != "" {
		snowTicket["u_suggested_fix"] = ticket.SuggestedFix
	}

	body, err := json.Marshal(snowTicket)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/api/now/table/incident", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ServiceNow API error: %d", resp.StatusCode)
	}

	var result struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &TicketResponse{
		TicketID:  result.Result.Number,
		TicketURL: c.BaseURL + "/nav_to.do?uri=incident.do?sys_id=" + result.Result.SysID,
		CreatedAt: time.Now(),
		Status:    "New",
	}, nil
}

// UpdateTicket updates an existing incident
func (c *ServiceNowClient) UpdateTicket(ticketID string, update *TicketUpdate) error {
	updateData := make(map[string]interface{})

	if update.Status != nil {
		updateData["state"] = mapStatusToState(*update.Status)
	}
	if update.AssignmentGroup != nil {
		updateData["assignment_group"] = *update.AssignmentGroup
	}
	if update.Assignee != nil {
		updateData["assigned_to"] = *update.Assignee
	}
	if update.Resolution != nil {
		updateData["close_notes"] = *update.Resolution
	}
	if update.WorkNotes != nil {
		updateData["work_notes"] = *update.WorkNotes
	}

	body, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", c.BaseURL+"/api/now/table/incident?sysparm_query=number="+ticketID, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ServiceNow API error: %d", resp.StatusCode)
	}

	return nil
}

// AddComment adds a comment to an incident
func (c *ServiceNowClient) AddComment(ticketID string, comment string) error {
	update := &TicketUpdate{
		WorkNotes: &comment,
	}
	return c.UpdateTicket(ticketID, update)
}

// AttachFile attaches a file to an incident
func (c *ServiceNowClient) AttachFile(ticketID string, filename string, content []byte) error {
	// ServiceNow attachment API
	req, err := http.NewRequest("POST", c.BaseURL+"/api/now/attachment/file?table_name=incident&table_sys_id="+ticketID+"&file_name="+filename, bytes.NewBuffer(content))
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ServiceNow attachment API error: %d", resp.StatusCode)
	}

	return nil
}

// GetTicket retrieves an incident by ID
func (c *ServiceNowClient) GetTicket(ticketID string) (*Ticket, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/now/table/incident?sysparm_query=number="+ticketID, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ServiceNow API error: %d", resp.StatusCode)
	}

	var result struct {
		Result []struct {
			Number           string `json:"number"`
			ShortDescription string `json:"short_description"`
			Description      string `json:"description"`
			State            string `json:"state"`
			Priority         string `json:"priority"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Result) == 0 {
		return nil, fmt.Errorf("ticket not found: %s", ticketID)
	}

	r := result.Result[0]
	return &Ticket{
		ID:          r.Number,
		Title:       r.ShortDescription,
		Description: r.Description,
		Status:      mapStateToStatus(r.State),
	}, nil
}

// JiraClient implements TicketingSystem for Jira Service Desk
type JiraClient struct {
	BaseURL    string
	Email      string
	APIToken   string
	ProjectKey string
	HTTPClient *http.Client
}

// NewJiraClient creates a new Jira client
func NewJiraClient(baseURL, email, apiToken, projectKey string) *JiraClient {
	return &JiraClient{
		BaseURL:    strings.TrimSuffix(baseURL, "/"),
		Email:      email,
		APIToken:   apiToken,
		ProjectKey: projectKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateTicket creates a new issue in Jira
func (c *JiraClient) CreateTicket(ticket *Ticket) (*TicketResponse, error) {
	jiraIssue := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{
				"key": c.ProjectKey,
			},
			"summary":     ticket.Title,
			"description": ticket.Description,
			"issuetype": map[string]string{
				"name": "Bug",
			},
			"priority": map[string]string{
				"name": mapPriorityToJira(ticket.Priority),
			},
			"labels": ticket.Tags,
		},
	}

	body, err := json.Marshal(jiraIssue)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/rest/api/3/issue", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.Email, c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Jira API error: %d", resp.StatusCode)
	}

	var result struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Self string `json:"self"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &TicketResponse{
		TicketID:  result.Key,
		TicketURL: c.BaseURL + "/browse/" + result.Key,
		CreatedAt: time.Now(),
		Status:    "Open",
	}, nil
}

// UpdateTicket updates an existing Jira issue
func (c *JiraClient) UpdateTicket(ticketID string, update *TicketUpdate) error {
	updateData := map[string]interface{}{
		"fields": map[string]interface{}{},
	}

	fields := updateData["fields"].(map[string]interface{})

	if update.Assignee != nil {
		fields["assignee"] = map[string]string{"name": *update.Assignee}
	}

	body, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", c.BaseURL+"/rest/api/3/issue/"+ticketID, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.Email, c.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Jira API error: %d", resp.StatusCode)
	}

	return nil
}

// AddComment adds a comment to a Jira issue
func (c *JiraClient) AddComment(ticketID string, comment string) error {
	commentData := map[string]interface{}{
		"body": comment,
	}

	body, err := json.Marshal(commentData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/rest/api/3/issue/"+ticketID+"/comment", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.Email, c.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Jira API error: %d", resp.StatusCode)
	}

	return nil
}

// AttachFile attaches a file to a Jira issue
func (c *JiraClient) AttachFile(ticketID string, filename string, content []byte) error {
	// Jira uses multipart form data for attachments
	// Simplified implementation
	return fmt.Errorf("Jira attachment not implemented in this version")
}

// GetTicket retrieves a Jira issue by key
func (c *JiraClient) GetTicket(ticketID string) (*Ticket, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/rest/api/3/issue/"+ticketID, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.Email, c.APIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Jira API error: %d", resp.StatusCode)
	}

	var result struct {
		Key    string `json:"key"`
		Fields struct {
			Summary     string `json:"summary"`
			Description string `json:"description"`
			Status      struct {
				Name string `json:"name"`
			} `json:"status"`
		} `json:"fields"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &Ticket{
		ID:          result.Key,
		Title:       result.Fields.Summary,
		Description: result.Fields.Description,
		Status:      TicketStatus(result.Fields.Status.Name),
	}, nil
}

// TicketBuilder helps construct tickets from detected issues
type TicketBuilder struct {
	ticket *Ticket
}

// NewTicketBuilder creates a new ticket builder
func NewTicketBuilder() *TicketBuilder {
	return &TicketBuilder{
		ticket: &Ticket{
			CustomFields: make(map[string]string),
			Tags:         make([]string, 0),
			CreatedAt:    time.Now(),
		},
	}
}

// FromDetectedIssue populates ticket from a detected issue
func (tb *TicketBuilder) FromDetectedIssue(issueID, title, description, businessImpact, severity, category string) *TicketBuilder {
	tb.ticket.Title = fmt.Sprintf("[%s] %s", issueID, title)
	tb.ticket.Description = fmt.Sprintf("## Issue Description\n%s\n\n## Business Impact\n%s", description, businessImpact)
	tb.ticket.Category = category
	tb.ticket.IssueType = issueID

	// Map severity to priority
	switch severity {
	case "Critical":
		tb.ticket.Priority = PriorityCritical
		tb.ticket.Severity = SeveritySev1
	case "High":
		tb.ticket.Priority = PriorityHigh
		tb.ticket.Severity = SeveritySev2
	case "Medium":
		tb.ticket.Priority = PriorityMedium
		tb.ticket.Severity = SeveritySev3
	default:
		tb.ticket.Priority = PriorityLow
		tb.ticket.Severity = SeveritySev4
	}

	tb.ticket.Tags = append(tb.ticket.Tags, "sdwan-triage", category, severity)

	return tb
}

// WithWiresharkFilter adds Wireshark filter to ticket
func (tb *TicketBuilder) WithWiresharkFilter(filter string) *TicketBuilder {
	tb.ticket.WiresharkFilter = filter
	tb.ticket.Description += fmt.Sprintf("\n\n## Wireshark Filter\n```\n%s\n```", filter)
	return tb
}

// WithRemediation adds remediation steps to ticket
func (tb *TicketBuilder) WithRemediation(steps []string) *TicketBuilder {
	tb.ticket.RemediationSteps = steps
	if len(steps) > 0 {
		tb.ticket.SuggestedFix = steps[0]
		tb.ticket.Description += "\n\n## Suggested Remediation\n"
		for i, step := range steps {
			tb.ticket.Description += fmt.Sprintf("%d. %s\n", i+1, step)
		}
	}
	return tb
}

// WithCustomer adds customer information
func (tb *TicketBuilder) WithCustomer(customerID, customerName string) *TicketBuilder {
	tb.ticket.CustomerID = customerID
	tb.ticket.CustomerName = customerName
	return tb
}

// WithSDWANVendor adds SD-WAN vendor information
func (tb *TicketBuilder) WithSDWANVendor(vendor string) *TicketBuilder {
	tb.ticket.SDWANVendor = vendor
	tb.ticket.Tags = append(tb.ticket.Tags, "vendor-"+strings.ToLower(vendor))
	return tb
}

// WithPcapFile adds PCAP file reference
func (tb *TicketBuilder) WithPcapFile(filename string) *TicketBuilder {
	tb.ticket.PcapFilename = filename
	return tb
}

// Build returns the constructed ticket
func (tb *TicketBuilder) Build() *Ticket {
	return tb.ticket
}

// Helper functions for mapping between systems

func mapPriorityToUrgency(priority TicketPriority) string {
	switch priority {
	case PriorityCritical:
		return "1"
	case PriorityHigh:
		return "2"
	case PriorityMedium:
		return "3"
	default:
		return "4"
	}
}

func mapSeverityToImpact(severity TicketSeverity) string {
	switch severity {
	case SeveritySev1:
		return "1"
	case SeveritySev2:
		return "2"
	case SeveritySev3:
		return "3"
	default:
		return "4"
	}
}

func mapStatusToState(status TicketStatus) string {
	switch status {
	case StatusNew:
		return "1"
	case StatusInProgress:
		return "2"
	case StatusPending:
		return "3"
	case StatusResolved:
		return "6"
	case StatusClosed:
		return "7"
	default:
		return "1"
	}
}

func mapStateToStatus(state string) TicketStatus {
	switch state {
	case "1":
		return StatusNew
	case "2":
		return StatusInProgress
	case "3":
		return StatusPending
	case "6":
		return StatusResolved
	case "7":
		return StatusClosed
	default:
		return StatusNew
	}
}

func mapPriorityToJira(priority TicketPriority) string {
	switch priority {
	case PriorityCritical:
		return "Highest"
	case PriorityHigh:
		return "High"
	case PriorityMedium:
		return "Medium"
	default:
		return "Low"
	}
}
