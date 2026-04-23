package ai

import (
	"fmt"
)

// DummyAIClient is a placeholder AI client for development/testing.
type DummyAIClient struct{}

func (d *DummyAIClient) ExplainFinding(finding string, context string) (string, error) {
	return fmt.Sprintf("[AI Remediation for: %s]\n- This is a placeholder. Configure a real AI provider for actionable guidance.\n- Context: %s", finding, context), nil
}
