package downstream

import (
	"context"
	"errors"
	"testing"
)

func TestMockToolsCatalog(t *testing.T) {
	m := NewMock()
	names := map[string]bool{}
	for _, tl := range m.Tools() {
		names[tl.Name] = true
	}
	for _, want := range []string{
		"github.list_repositories", "github.create_issue",
		"github.delete_repository", "payroll.get_employee",
	} {
		if !names[want] {
			t.Errorf("missing tool %q in catalog", want)
		}
	}
}

func TestMockCallKnown(t *testing.T) {
	m := NewMock()
	res, err := m.Call(context.Background(), "payroll.get_employee", map[string]any{"employee_id": "e-1"})
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := res.(map[string]any)
	if !ok || rec["employee_id"] != "e-1" {
		t.Fatalf("unexpected result: %v", res)
	}
}

func TestMockCallUnknown(t *testing.T) {
	m := NewMock()
	_, err := m.Call(context.Background(), "nope.tool", nil)
	var unknown *ErrUnknownTool
	if !errors.As(err, &unknown) {
		t.Fatalf("expected ErrUnknownTool, got %v", err)
	}
}

func TestMockRequiredArgs(t *testing.T) {
	m := NewMock()
	if _, err := m.Call(context.Background(), "github.create_issue", map[string]any{"repo": "acme/docs"}); err == nil {
		t.Fatal("expected error when required title is missing")
	}
}
