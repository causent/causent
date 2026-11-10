package diagnosis

import "testing"

func TestParseRaceReportsPreservesReadWriteAndCreationStacks(t *testing.T) {
	text := `WARNING: DATA RACE
Read at 0x00 by goroutine 8:
  pkg/cache.read(cache.go:12)

Previous write at 0x00 by goroutine 9:
  pkg/cache.write(cache.go:30)

Goroutine 8 (running) created at:
  testing.tRunner(testing.go:100)
`
	reports := parseRaceReports(text)
	if len(reports) != 1 || len(reports[0].ReadStack) != 1 || len(reports[0].WriteStack) != 1 {
		t.Fatalf("race sides were collapsed: %#v", reports)
	}
	if reports[0].ReadStack[0].Line != 12 || reports[0].WriteStack[0].Line != 30 {
		t.Fatalf("wrong race locations: %#v", reports[0])
	}
	if len(reports[0].GoroutineCreationStacks) != 1 || len(reports[0].GoroutineCreationStacks[0]) != 1 {
		t.Fatalf("creation stack missing: %#v", reports[0])
	}
}
