package diagnosis

import (
	"encoding/xml"
	"fmt"
)

type junitDocument struct {
	Suites []junitSuite `xml:"testsuite"`
}
type junitSuite struct {
	XMLName xml.Name     `xml:""`
	Name    string       `xml:"name,attr"`
	Cases   []junitCase  `xml:"testcase"`
	Suites  []junitSuite `xml:"testsuite"`
}
type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitProblem `xml:"failure"`
	Error     *junitProblem `xml:"error"`
	Skipped   *struct{}     `xml:"skipped"`
}
type junitProblem struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

// parseJUnitFailures converts standard JUnit XML results into the same failure
// observation contract used by text CI logs. It preserves test identity and
// does not infer a cause.
func parseJUnitFailures(data string) ([]failureObservation, error) {
	var document junitDocument
	if err := xml.Unmarshal([]byte(data), &document); err != nil {
		return nil, fmt.Errorf("parse junit XML: %w", err)
	}
	var observations []failureObservation
	var visit func(junitSuite)
	visit = func(suite junitSuite) {
		for _, testcase := range suite.Cases {
			problem := testcase.Failure
			if problem == nil {
				problem = testcase.Error
			}
			if problem == nil {
				continue
			}
			name := testcase.ClassName
			if name != "" {
				name += "::"
			}
			name += testcase.Name
			message := problem.Message
			if message == "" {
				message = problem.Body
			}
			observations = append(observations, failureObservation{Test: name, Message: message})
		}
		for _, nested := range suite.Suites {
			visit(nested)
		}
	}
	for _, suite := range document.Suites {
		visit(suite)
	}
	return observations, nil
}
