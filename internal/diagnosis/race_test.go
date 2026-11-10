package diagnosis

import (
	"os"
	"testing"
)

func TestParseRaceReportsPreservesReadWriteAndCreationStacks(t *testing.T) {
	data, err := os.ReadFile("testdata/kubernetes-race.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	reports := parseRaceReports(text)
	if len(reports) != 1 || len(reports[0].ReadStack) != 1 || len(reports[0].WriteStack) != 1 {
		t.Fatalf("race sides were collapsed: %#v", reports)
	}
	if reports[0].ReadStack[0].Line != 496 || reports[0].WriteStack[0].Line != 187 {
		t.Fatalf("wrong race locations: %#v", reports[0])
	}
	if len(reports[0].GoroutineCreationStacks) != 1 || len(reports[0].GoroutineCreationStacks[0]) < 2 {
		t.Fatalf("creation stack missing: %#v", reports[0])
	}
	if reports[0].Test != "TestWatch/WatchCacheStallResume=true/WatchWithoutPrevKV=true/ClusterScopedWatch" || reports[0].ReadAccessType != "read" || reports[0].WriteAccessType != "write" {
		t.Fatalf("race metadata missing: %#v", reports[0])
	}
}

func TestParseRaceReportsHandlesMultipleAndIncompleteReports(t *testing.T) {
	text := `WARNING: DATA RACE
Read at 0x00 by goroutine 1:
  pkg/a()
      /workspace/a.go:10 +0x1
Previous write at 0x00 by goroutine 2:
  pkg/b()
      /workspace/b.go:20 +0x1
WARNING: DATA RACE
Read at 0x00 by goroutine 3:
  pkg/c()
`
	reports := parseRaceReports(text)
	if len(reports) != 2 {
		t.Fatalf("reports = %d, want 2: %#v", len(reports), reports)
	}
	if len(reports[1].ReadStack) != 0 {
		t.Fatalf("incomplete location invented: %#v", reports[1])
	}
}
