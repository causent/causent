package diagnosis

import "testing"

func TestParseJUnitFailuresPreservesMultipleTests(t *testing.T) {
	observations, err := parseJUnitFailures(`<testsuites><testsuite name="unit"><testcase classname="pkg.Test" name="One"><failure message="expected one">trace</failure></testcase><testcase classname="pkg.Test" name="Two"><error message="boom"/></testcase></testsuite></testsuites>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 || observations[0].Test != "pkg.Test::One" || observations[1].Test != "pkg.Test::Two" {
		t.Fatalf("observations=%#v", observations)
	}
}
