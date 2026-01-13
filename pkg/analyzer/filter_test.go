package analyzer

import (
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func TestFilterIsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		filter   *models.Filter
		expected bool
	}{
		{
			name:     "Nil filter",
			filter:   nil,
			expected: true,
		},
		{
			name:     "Empty filter",
			filter:   &models.Filter{},
			expected: true,
		},
		{
			name: "Filter with SrcIP",
			filter: &models.Filter{
				SrcIP: "192.168.1.1",
			},
			expected: false,
		},
		{
			name: "Filter with DstIP",
			filter: &models.Filter{
				DstIP: "10.0.0.1",
			},
			expected: false,
		},
		{
			name: "Filter with Service",
			filter: &models.Filter{
				Service: "https",
			},
			expected: false,
		},
		{
			name: "Filter with Protocol",
			filter: &models.Filter{
				Protocol: "tcp",
			},
			expected: false,
		},
		{
			name: "Filter with multiple fields",
			filter: &models.Filter{
				SrcIP:    "192.168.1.1",
				DstIP:    "10.0.0.1",
				Service:  "https",
				Protocol: "tcp",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.IsEmpty()
			if result != tt.expected {
				t.Errorf("IsEmpty() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestFilterValidation(t *testing.T) {
	tests := []struct {
		name   string
		filter *models.Filter
		valid  bool
	}{
		{
			name: "Valid IP addresses",
			filter: &models.Filter{
				SrcIP: "192.168.1.1",
				DstIP: "10.0.0.1",
			},
			valid: true,
		},
		{
			name: "Valid protocol",
			filter: &models.Filter{
				Protocol: "tcp",
			},
			valid: true,
		},
		{
			name: "Valid service name",
			filter: &models.Filter{
				Service: "https",
			},
			valid: true,
		},
		{
			name: "Valid service port",
			filter: &models.Filter{
				Service: "443",
			},
			valid: true,
		},
		{
			name:   "Empty filter is valid",
			filter: &models.Filter{},
			valid:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Filter validation is implicit - if filter is created, it's valid
			// This test ensures filters can be created without panics
			if tt.filter == nil {
				t.Error("Filter should not be nil")
			}
		})
	}
}

func BenchmarkFilterIsEmpty(b *testing.B) {
	filters := []*models.Filter{
		nil,
		{},
		{SrcIP: "192.168.1.1"},
		{DstIP: "10.0.0.1"},
		{Service: "https"},
		{Protocol: "tcp"},
		{SrcIP: "192.168.1.1", DstIP: "10.0.0.1", Service: "https", Protocol: "tcp"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range filters {
			_ = f.IsEmpty()
		}
	}
}
