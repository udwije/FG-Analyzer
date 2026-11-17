package main

import (
	"strings"
	"testing"
)

func TestMigrationStepsAreCheckable(t *testing.T) {
	steps := migrationSteps(schemaSQL)
	if len(steps) < 60 {
		t.Fatalf("only %d steps", len(steps))
	}
	unchecked := 0
	for _, s := range steps {
		if strings.HasPrefix(s.sql, "--") || strings.TrimSpace(s.sql) == "" {
			t.Errorf("comment or empty step: %q", s.sql)
		}
		u := strings.ToUpper(s.sql)
		if strings.HasPrefix(u, "ALTER TABLE") || strings.HasPrefix(u, "CREATE") || strings.HasPrefix(u, "DROP") {
			if s.check == "" {
				unchecked++
				t.Errorf("step without a check: %s", s.label)
			}
		}
		if strings.Contains(s.sql, "fortigate_logs") && strings.HasPrefix(u, "ALTER TABLE") && s.table != "fortigate_logs" {
			t.Errorf("table not detected: %s", s.label)
		}
	}
	for _, s := range steps {
		if strings.Contains(s.sql, "idx_r1h_dim_hour") {
			t.Error("the redundant rollup_1h index must not be created any more")
		}
	}
	f := 0
	for _, s := range steps {
		if strings.HasPrefix(s.label, "function ") {
			f++
			if !strings.Contains(s.check, "prosrc") || strings.Contains(s.check, "$fn$") {
				t.Errorf("function check: %s", s.check)
			}
		}
	}
	if f != 2 {
		t.Errorf("functions: %d", f)
	}
}
