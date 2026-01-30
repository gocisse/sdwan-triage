package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AutomationTrigger represents an automated action trigger
type AutomationTrigger struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	Description     string             `json:"description"`
	Enabled         bool               `json:"enabled"`
	Conditions      []TriggerCondition `json:"conditions"`
	Actions         []AutomationAction `json:"actions"`
	Cooldown        time.Duration      `json:"cooldown"`
	LastTriggered   time.Time          `json:"last_triggered"`
	TriggerCount    int64              `json:"trigger_count"`
	SuccessCount    int64              `json:"success_count"`
	FailureCount    int64              `json:"failure_count"`
	RequireApproval bool               `json:"require_approval"`
}

// TriggerCondition defines when a trigger should fire
type TriggerCondition struct {
	Type      ConditionType `json:"type"`
	Field     string        `json:"field"`
	Operator  string        `json:"operator"` // "equals", "contains", "greater_than", "less_than"
	Value     interface{}   `json:"value"`
	LogicalOp string        `json:"logical_op,omitempty"` // "AND", "OR"
}

// ConditionType categorizes trigger conditions
type ConditionType string

const (
	ConditionIssueDetected ConditionType = "issue_detected"
	ConditionHealthScore   ConditionType = "health_score"
	ConditionSeverity      ConditionType = "severity"
	ConditionCategory      ConditionType = "category"
	ConditionVendor        ConditionType = "vendor"
	ConditionSuccessRate   ConditionType = "success_rate"
	ConditionCustomerID    ConditionType = "customer_id"
)

// AutomationAction defines what action to take
type AutomationAction struct {
	Type      ActionType             `json:"type"`
	Config    map[string]interface{} `json:"config"`
	OnSuccess []AutomationAction     `json:"on_success,omitempty"`
	OnFailure []AutomationAction     `json:"on_failure,omitempty"`
	Timeout   time.Duration          `json:"timeout,omitempty"`
}

// ActionType categorizes automation actions
type ActionType string

const (
	ActionCreateTicket   ActionType = "create_ticket"
	ActionSendWebhook    ActionType = "send_webhook"
	ActionExecuteCommand ActionType = "execute_command"
	ActionSendEmail      ActionType = "send_email"
	ActionSendSlack      ActionType = "send_slack"
	ActionUpdatePolicy   ActionType = "update_policy"
	ActionRestartService ActionType = "restart_service"
	ActionBlockTraffic   ActionType = "block_traffic"
	ActionEscalate       ActionType = "escalate"
	ActionLogEvent       ActionType = "log_event"
)

// TriggerEvent contains data that triggers automation
type TriggerEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	IssueID     string                 `json:"issue_id,omitempty"`
	IssueTitle  string                 `json:"issue_title,omitempty"`
	Severity    string                 `json:"severity,omitempty"`
	Category    string                 `json:"category,omitempty"`
	HealthScore float64                `json:"health_score,omitempty"`
	CustomerID  string                 `json:"customer_id,omitempty"`
	Vendor      string                 `json:"vendor,omitempty"`
	SuccessRate float64                `json:"success_rate,omitempty"`
	StreamData  map[string]interface{} `json:"stream_data,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ActionResult contains the result of an automation action
type ActionResult struct {
	ActionType ActionType    `json:"action_type"`
	Success    bool          `json:"success"`
	Message    string        `json:"message"`
	Data       interface{}   `json:"data,omitempty"`
	Duration   time.Duration `json:"duration"`
	Error      string        `json:"error,omitempty"`
}

// AutomationEngine manages and executes automation triggers
type AutomationEngine struct {
	triggers       map[string]*AutomationTrigger
	mu             sync.RWMutex
	actionHandlers map[ActionType]ActionHandler
	eventChan      chan TriggerEvent
	resultChan     chan ActionResult
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup

	// Integration clients
	ticketingClient TicketingSystem
	webhookClient   *WebhookClient
}

// ActionHandler is a function that executes an action
type ActionHandler func(ctx context.Context, action AutomationAction, event TriggerEvent) ActionResult

// NewAutomationEngine creates a new automation engine
func NewAutomationEngine() *AutomationEngine {
	ctx, cancel := context.WithCancel(context.Background())

	engine := &AutomationEngine{
		triggers:       make(map[string]*AutomationTrigger),
		actionHandlers: make(map[ActionType]ActionHandler),
		eventChan:      make(chan TriggerEvent, 100),
		resultChan:     make(chan ActionResult, 100),
		ctx:            ctx,
		cancel:         cancel,
		webhookClient:  NewWebhookClient(),
	}

	// Register default action handlers
	engine.registerDefaultHandlers()

	return engine
}

// registerDefaultHandlers registers built-in action handlers
func (ae *AutomationEngine) registerDefaultHandlers() {
	ae.actionHandlers[ActionSendWebhook] = ae.handleWebhook
	ae.actionHandlers[ActionLogEvent] = ae.handleLogEvent
	ae.actionHandlers[ActionCreateTicket] = ae.handleCreateTicket
	ae.actionHandlers[ActionSendSlack] = ae.handleSendSlack
	ae.actionHandlers[ActionEscalate] = ae.handleEscalate
}

// SetTicketingClient sets the ticketing system client
func (ae *AutomationEngine) SetTicketingClient(client TicketingSystem) {
	ae.ticketingClient = client
}

// RegisterTrigger adds a new automation trigger
func (ae *AutomationEngine) RegisterTrigger(trigger *AutomationTrigger) {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	ae.triggers[trigger.ID] = trigger
}

// RemoveTrigger removes an automation trigger
func (ae *AutomationEngine) RemoveTrigger(triggerID string) {
	ae.mu.Lock()
	defer ae.mu.Unlock()
	delete(ae.triggers, triggerID)
}

// EnableTrigger enables a trigger
func (ae *AutomationEngine) EnableTrigger(triggerID string) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	trigger, exists := ae.triggers[triggerID]
	if !exists {
		return fmt.Errorf("trigger not found: %s", triggerID)
	}
	trigger.Enabled = true
	return nil
}

// DisableTrigger disables a trigger
func (ae *AutomationEngine) DisableTrigger(triggerID string) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	trigger, exists := ae.triggers[triggerID]
	if !exists {
		return fmt.Errorf("trigger not found: %s", triggerID)
	}
	trigger.Enabled = false
	return nil
}

// Start begins processing events
func (ae *AutomationEngine) Start() {
	ae.wg.Add(1)
	go ae.processEvents()
}

// Stop gracefully shuts down the engine
func (ae *AutomationEngine) Stop() {
	ae.cancel()
	close(ae.eventChan)
	ae.wg.Wait()
	close(ae.resultChan)
}

// SubmitEvent submits an event for processing
func (ae *AutomationEngine) SubmitEvent(event TriggerEvent) {
	select {
	case ae.eventChan <- event:
	case <-ae.ctx.Done():
	}
}

// Results returns the result channel
func (ae *AutomationEngine) Results() <-chan ActionResult {
	return ae.resultChan
}

// processEvents processes incoming events
func (ae *AutomationEngine) processEvents() {
	defer ae.wg.Done()

	for {
		select {
		case <-ae.ctx.Done():
			return
		case event, ok := <-ae.eventChan:
			if !ok {
				return
			}
			ae.evaluateTriggers(event)
		}
	}
}

// evaluateTriggers checks all triggers against an event
func (ae *AutomationEngine) evaluateTriggers(event TriggerEvent) {
	ae.mu.RLock()
	triggers := make([]*AutomationTrigger, 0, len(ae.triggers))
	for _, t := range ae.triggers {
		triggers = append(triggers, t)
	}
	ae.mu.RUnlock()

	for _, trigger := range triggers {
		if !trigger.Enabled {
			continue
		}

		// Check cooldown
		if time.Since(trigger.LastTriggered) < trigger.Cooldown {
			continue
		}

		// Evaluate conditions
		if ae.evaluateConditions(trigger.Conditions, event) {
			ae.executeTrigger(trigger, event)
		}
	}
}

// evaluateConditions checks if all conditions are met
func (ae *AutomationEngine) evaluateConditions(conditions []TriggerCondition, event TriggerEvent) bool {
	if len(conditions) == 0 {
		return true
	}

	result := true
	for i, condition := range conditions {
		conditionMet := ae.evaluateCondition(condition, event)

		if i == 0 {
			result = conditionMet
		} else {
			switch condition.LogicalOp {
			case "OR":
				result = result || conditionMet
			default: // AND
				result = result && conditionMet
			}
		}
	}

	return result
}

// evaluateCondition evaluates a single condition
func (ae *AutomationEngine) evaluateCondition(condition TriggerCondition, event TriggerEvent) bool {
	var fieldValue interface{}

	// Get field value from event
	switch condition.Type {
	case ConditionIssueDetected:
		fieldValue = event.IssueID
	case ConditionHealthScore:
		fieldValue = event.HealthScore
	case ConditionSeverity:
		fieldValue = event.Severity
	case ConditionCategory:
		fieldValue = event.Category
	case ConditionVendor:
		fieldValue = event.Vendor
	case ConditionSuccessRate:
		fieldValue = event.SuccessRate
	case ConditionCustomerID:
		fieldValue = event.CustomerID
	default:
		return false
	}

	// Evaluate operator
	switch condition.Operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", condition.Value)
	case "not_equals":
		return fmt.Sprintf("%v", fieldValue) != fmt.Sprintf("%v", condition.Value)
	case "contains":
		return containsString(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", condition.Value))
	case "greater_than":
		return compareNumeric(fieldValue, condition.Value) > 0
	case "less_than":
		return compareNumeric(fieldValue, condition.Value) < 0
	case "exists":
		return fieldValue != nil && fieldValue != ""
	default:
		return false
	}
}

// executeTrigger executes all actions for a trigger
func (ae *AutomationEngine) executeTrigger(trigger *AutomationTrigger, event TriggerEvent) {
	ae.mu.Lock()
	trigger.LastTriggered = time.Now()
	trigger.TriggerCount++
	ae.mu.Unlock()

	allSuccess := true
	for _, action := range trigger.Actions {
		result := ae.executeAction(action, event)

		select {
		case ae.resultChan <- result:
		case <-ae.ctx.Done():
			return
		}

		if !result.Success {
			allSuccess = false
			// Execute failure actions
			for _, failAction := range action.OnFailure {
				ae.executeAction(failAction, event)
			}
		} else {
			// Execute success actions
			for _, successAction := range action.OnSuccess {
				ae.executeAction(successAction, event)
			}
		}
	}

	ae.mu.Lock()
	if allSuccess {
		trigger.SuccessCount++
	} else {
		trigger.FailureCount++
	}
	ae.mu.Unlock()
}

// executeAction executes a single action
func (ae *AutomationEngine) executeAction(action AutomationAction, event TriggerEvent) ActionResult {
	handler, exists := ae.actionHandlers[action.Type]
	if !exists {
		return ActionResult{
			ActionType: action.Type,
			Success:    false,
			Error:      "no handler registered for action type",
		}
	}

	timeout := action.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ae.ctx, timeout)
	defer cancel()

	start := time.Now()
	result := handler(ctx, action, event)
	result.Duration = time.Since(start)

	return result
}

// Action handlers

func (ae *AutomationEngine) handleWebhook(ctx context.Context, action AutomationAction, event TriggerEvent) ActionResult {
	url, _ := action.Config["url"].(string)
	if url == "" {
		return ActionResult{
			ActionType: ActionSendWebhook,
			Success:    false,
			Error:      "webhook URL not configured",
		}
	}

	err := ae.webhookClient.Send(ctx, url, event)
	if err != nil {
		return ActionResult{
			ActionType: ActionSendWebhook,
			Success:    false,
			Error:      err.Error(),
		}
	}

	return ActionResult{
		ActionType: ActionSendWebhook,
		Success:    true,
		Message:    "Webhook sent successfully",
	}
}

func (ae *AutomationEngine) handleLogEvent(ctx context.Context, action AutomationAction, event TriggerEvent) ActionResult {
	// Log the event (in production, this would write to a log system)
	message := fmt.Sprintf("[AUTOMATION] Event: %s, Issue: %s, Severity: %s",
		event.EventType, event.IssueID, event.Severity)

	return ActionResult{
		ActionType: ActionLogEvent,
		Success:    true,
		Message:    message,
	}
}

func (ae *AutomationEngine) handleCreateTicket(ctx context.Context, action AutomationAction, event TriggerEvent) ActionResult {
	if ae.ticketingClient == nil {
		return ActionResult{
			ActionType: ActionCreateTicket,
			Success:    false,
			Error:      "ticketing client not configured",
		}
	}

	// Build ticket from event
	builder := NewTicketBuilder().
		FromDetectedIssue(event.IssueID, event.IssueTitle, "", "", event.Severity, event.Category).
		WithCustomer(event.CustomerID, "").
		WithSDWANVendor(event.Vendor)

	ticket := builder.Build()

	response, err := ae.ticketingClient.CreateTicket(ticket)
	if err != nil {
		return ActionResult{
			ActionType: ActionCreateTicket,
			Success:    false,
			Error:      err.Error(),
		}
	}

	return ActionResult{
		ActionType: ActionCreateTicket,
		Success:    true,
		Message:    "Ticket created: " + response.TicketID,
		Data:       response,
	}
}

func (ae *AutomationEngine) handleSendSlack(ctx context.Context, action AutomationAction, event TriggerEvent) ActionResult {
	webhookURL, _ := action.Config["webhook_url"].(string)
	channel, _ := action.Config["channel"].(string)

	if webhookURL == "" {
		return ActionResult{
			ActionType: ActionSendSlack,
			Success:    false,
			Error:      "Slack webhook URL not configured",
		}
	}

	// Build Slack message
	message := map[string]interface{}{
		"channel": channel,
		"text":    fmt.Sprintf("🚨 *SD-WAN Alert*: %s", event.IssueTitle),
		"attachments": []map[string]interface{}{
			{
				"color": getSeverityColor(event.Severity),
				"fields": []map[string]interface{}{
					{"title": "Issue ID", "value": event.IssueID, "short": true},
					{"title": "Severity", "value": event.Severity, "short": true},
					{"title": "Category", "value": event.Category, "short": true},
					{"title": "Customer", "value": event.CustomerID, "short": true},
				},
			},
		},
	}

	err := ae.webhookClient.SendJSON(ctx, webhookURL, message)
	if err != nil {
		return ActionResult{
			ActionType: ActionSendSlack,
			Success:    false,
			Error:      err.Error(),
		}
	}

	return ActionResult{
		ActionType: ActionSendSlack,
		Success:    true,
		Message:    "Slack notification sent",
	}
}

func (ae *AutomationEngine) handleEscalate(ctx context.Context, action AutomationAction, event TriggerEvent) ActionResult {
	escalationLevel, _ := action.Config["level"].(string)
	notifyEmail, _ := action.Config["notify_email"].(string)

	message := fmt.Sprintf("Escalation triggered for issue %s to level %s", event.IssueID, escalationLevel)

	// In production, this would send email or page on-call
	if notifyEmail != "" {
		message += fmt.Sprintf(", notification sent to %s", notifyEmail)
	}

	return ActionResult{
		ActionType: ActionEscalate,
		Success:    true,
		Message:    message,
	}
}

// WebhookClient handles webhook delivery
type WebhookClient struct {
	httpClient *http.Client
}

// NewWebhookClient creates a new webhook client
func NewWebhookClient() *WebhookClient {
	return &WebhookClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Send sends an event to a webhook URL
func (wc *WebhookClient) Send(ctx context.Context, url string, event TriggerEvent) error {
	return wc.SendJSON(ctx, url, event)
}

// SendJSON sends JSON data to a webhook URL
func (wc *WebhookClient) SendJSON(ctx context.Context, url string, data interface{}) error {
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Body = http.NoBody

	// Create new request with body
	req, err = http.NewRequestWithContext(ctx, "POST", url, jsonReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := wc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// Helper functions

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func compareNumeric(a, b interface{}) int {
	aFloat := toFloat64(a)
	bFloat := toFloat64(b)

	if aFloat > bFloat {
		return 1
	} else if aFloat < bFloat {
		return -1
	}
	return 0
}

func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case uint64:
		return float64(val)
	default:
		return 0
	}
}

func getSeverityColor(severity string) string {
	switch severity {
	case "Critical":
		return "#FF0000"
	case "High":
		return "#FF6600"
	case "Medium":
		return "#FFCC00"
	case "Low":
		return "#00CC00"
	default:
		return "#808080"
	}
}

type jsonReaderStruct struct {
	data []byte
	pos  int
}

func jsonReader(data []byte) *jsonReaderStruct {
	return &jsonReaderStruct{data: data}
}

func (r *jsonReaderStruct) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// CreateDefaultTriggers creates common automation triggers
func CreateDefaultTriggers() []*AutomationTrigger {
	return []*AutomationTrigger{
		{
			ID:          "critical-issue-alert",
			Name:        "Critical Issue Alert",
			Description: "Send alert when critical issue detected",
			Enabled:     true,
			Conditions: []TriggerCondition{
				{Type: ConditionSeverity, Operator: "equals", Value: "Critical"},
			},
			Actions: []AutomationAction{
				{Type: ActionLogEvent},
				{Type: ActionSendSlack, Config: map[string]interface{}{"channel": "#sdwan-alerts"}},
			},
			Cooldown: 5 * time.Minute,
		},
		{
			ID:          "low-health-ticket",
			Name:        "Low Health Score Ticket",
			Description: "Create ticket when health score drops below 50",
			Enabled:     true,
			Conditions: []TriggerCondition{
				{Type: ConditionHealthScore, Operator: "less_than", Value: 50.0},
			},
			Actions: []AutomationAction{
				{Type: ActionCreateTicket},
			},
			Cooldown:        30 * time.Minute,
			RequireApproval: true,
		},
		{
			ID:          "vendor-specific-escalation",
			Name:        "Vendor-Specific Escalation",
			Description: "Escalate Cisco Viptela issues to vendor TAC",
			Enabled:     false,
			Conditions: []TriggerCondition{
				{Type: ConditionVendor, Operator: "equals", Value: "Cisco Viptela"},
				{Type: ConditionSeverity, Operator: "equals", Value: "Critical", LogicalOp: "AND"},
			},
			Actions: []AutomationAction{
				{Type: ActionEscalate, Config: map[string]interface{}{"level": "vendor_tac"}},
			},
			Cooldown: 1 * time.Hour,
		},
	}
}
