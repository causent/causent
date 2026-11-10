package diagnosis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/causent/malenia/internal/domain"
	programrepo "github.com/causent/malenia/internal/repository"
)

var sourceIdentifierRE = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\b`)
var sourceFieldRE = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\b`)

type sourceAccessTarget struct {
	Access      string
	File        string
	Line        int
	Address     string
	FrameRole   string
	ExactSource bool
}

type sourceAccessObservation struct {
	target                    sourceAccessTarget
	line                      string
	expression                string
	exactMemory               bool
	memoryIdentity            string
	frameRole                 string
	relatedIdentifiers        []string
	synchronizationEvidenceID string
	facts                     []string
}

// runSourceInvestigation performs bounded, deterministic inspection after
// localization. Actions are evidence-producing observations; objective
// predicates, evaluated after each observation, decide whether they resolved
// anything. Retrieval and action completion are never treated as proof.
func (d *Diagnoser) runSourceInvestigation(ctx context.Context, report *Report, workspace string, snapshot programrepo.Snapshot, candidates []domain.CandidateLocation, persist bool) error {
	if workspace == "" || ctx.Err() != nil {
		return ctx.Err()
	}
	targets := sourceInvestigationTargets(report, candidates)
	if len(targets) == 0 {
		return nil
	}
	beginInvestigationObjective(report)
	var accesses []sourceAccessObservation
	model := &ConcurrencyModel{}

	for index, target := range targets {
		if index >= 4 || ctx.Err() != nil {
			break
		}
		path := filepath.Join(workspace, filepath.FromSlash(target.File))
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		if target.Line < 1 || target.Line > len(lines) {
			continue
		}
		node := enclosingSourceNode(snapshot.Nodes, target.File, target.Line)
		if node == nil {
			continue
		}
		start, end := node.StartLine, node.EndLine
		if start < 1 {
			start = 1
		}
		if end > len(lines) || end < start {
			end = len(lines)
		}
		functionText := numberedSource(lines, start, end)
		expression := goAccessExpression(path, target.Line)
		if expression == "" {
			expression = strings.TrimSpace(lines[target.Line-1])
		}
		exactMemory, memoryIdentity := sourceMemoryIdentity(path, target.Line, expression)
		functionEvidence, err := d.recordSourceAction(ctx, report, persist, "InspectFunction", target.File+":"+fmt.Sprint(target.Line),
			fmt.Sprintf("complete enclosing %s %s (%s:%d-%d)", node.Type, node.Name, target.File, start, end),
			"source function", target.File, "access expression: "+expression+"\n"+functionText)
		if err != nil {
			return err
		}
		facts := []string{functionEvidence}
		accessLine := lines[target.Line-1]
		accesses = append(accesses, sourceAccessObservation{target: target, line: accessLine, expression: expression, exactMemory: exactMemory, memoryIdentity: memoryIdentity, frameRole: target.FrameRole, facts: facts})
		model.Accesses = append(model.Accesses, ConcurrencyAccess{Access: target.Access, File: target.File, Line: target.Line, Function: node.Identity, Expression: expression, ExactMemory: exactMemory, MemoryIdentity: memoryIdentity, FrameRole: target.FrameRole, StateIdentifiers: sourceStateIdentifiers(expression), EvidenceIDs: []string{functionEvidence}})

		variables := sourceVariables(accessLine)
		trace := traceVariables(lines, variables)
		if len(trace) > 0 {
			id, err := d.recordSourceAction(ctx, report, persist, "TraceVariable", target.File+":"+fmt.Sprint(target.Line),
				"trace identifiers used by the observed access through declarations, assignments, and references",
				"source variable trace", target.File, strings.Join(trace, "\n"))
			if err != nil {
				return err
			}
			accesses[len(accesses)-1].facts = append(accesses[len(accesses)-1].facts, id)
		}

		refs := referenceLines(lines, variables)
		if len(refs) > 0 {
			id, err := d.recordSourceAction(ctx, report, persist, "FindReferences", target.File+":"+fmt.Sprint(target.Line),
				"find references to identifiers used by the observed access",
				"source references", target.File, strings.Join(refs, "\n"))
			if err != nil {
				return err
			}
			accesses[len(accesses)-1].facts = append(accesses[len(accesses)-1].facts, id)
		}

		syncLines := synchronizationLines(lines, start, end)
		syncEvidence := "no synchronization operation was found inside the enclosing function; this is not proof that no synchronization exists elsewhere"
		if len(syncLines) > 0 {
			syncEvidence = "synchronization and ordering operations in the enclosing function:\n" + strings.Join(syncLines, "\n")
		}
		id, err := d.recordSourceAction(ctx, report, persist, "InspectSynchronization", target.File+":"+fmt.Sprint(target.Line),
			"inspect locks, atomics, channels, and wait operations around the observed access",
			"source synchronization", target.File, syncEvidence)
		if err != nil {
			return err
		}
		accesses[len(accesses)-1].facts = append(accesses[len(accesses)-1].facts, id)
		accesses[len(accesses)-1].synchronizationEvidenceID = id
		model.Synchronization = append(model.Synchronization, syncLines...)
		model.EvidenceIDs = appendUniqueString(model.EvidenceIDs, id)

		lifecycle := lifecycleLines(lines, start, end)
		if len(lifecycle) == 0 {
			lifecycle = []string{"no goroutine, cancellation, wait, or cleanup operation found in the enclosing function; callers remain unresolved"}
		}
		id, err = d.recordSourceAction(ctx, report, persist, "InspectGoroutineLifecycle", target.File+":"+fmt.Sprint(target.Line),
			"inspect goroutine creation, cancellation, waiting, and cleanup around the observed access",
			"source lifecycle", target.File, strings.Join(lifecycle, "\n"))
		if err != nil {
			return err
		}
		accesses[len(accesses)-1].facts = append(accesses[len(accesses)-1].facts, id)

		relations := relatedCallFacts(snapshot.Relationships, node.ID, snapshot.Nodes)
		if len(relations) > 0 {
			id, err = d.recordSourceAction(ctx, report, persist, "TraceCallers", node.Identity,
				"trace verified static callers; these relationships are not runtime observations",
				"source callers", target.File, strings.Join(relations, "\n"))
			if err != nil {
				return err
			}
			accesses[len(accesses)-1].facts = append(accesses[len(accesses)-1].facts, id)
			id, err = d.recordSourceAction(ctx, report, persist, "TraceCallees", node.Identity,
				"trace verified static callees; these relationships are not runtime observations",
				"source callees", target.File, strings.Join(relations, "\n"))
			if err != nil {
				return err
			}
			accesses[len(accesses)-1].facts = append(accesses[len(accesses)-1].facts, id)
		}
		for _, related := range relatedImplementationNodes(snapshot, node, expression) {
			relatedPath := filepath.Join(workspace, filepath.FromSlash(related.FilePath))
			relatedData, readErr := os.ReadFile(relatedPath)
			if readErr != nil {
				continue
			}
			relatedLines := strings.Split(string(relatedData), "\n")
			if related.StartLine < 1 || related.EndLine < related.StartLine || related.StartLine > len(relatedLines) {
				continue
			}
			relatedEnd := related.EndLine
			if relatedEnd > len(relatedLines) {
				relatedEnd = len(relatedLines)
			}
			detail := numberedSource(relatedLines, related.StartLine, relatedEnd)
			relatedID, relatedErr := d.recordSourceAction(ctx, report, persist, "InspectFunction", related.Identity,
				"inspect resolved related function implementation", "source related function", related.FilePath, detail)
			if relatedErr != nil {
				return relatedErr
			}
			accesses[len(accesses)-1].facts = append(accesses[len(accesses)-1].facts, relatedID)
			accesses[len(accesses)-1].relatedIdentifiers = append(accesses[len(accesses)-1].relatedIdentifiers, sourceStateIdentifiers(detail)...)
			sync := synchronizationLines(relatedLines, related.StartLine, relatedEnd)
			model.Synchronization = append(model.Synchronization, sync...)
			model.EvidenceIDs = appendUniqueString(model.EvidenceIDs, relatedID)
			if strings.Contains(detail, "go ") {
				model.GoroutineOwnership = append(model.GoroutineOwnership, related.Identity+" contains goroutine creation/ownership logic")
			}
		}

		cleanup := cleanupLines(lines, start, end)
		if len(cleanup) == 0 {
			cleanup = []string{"no explicit cleanup operation found in the enclosing function; cleanup ownership is unresolved"}
		}
		id, err = d.recordSourceAction(ctx, report, persist, "InspectCleanup", target.File+":"+fmt.Sprint(target.Line),
			"inspect defer, close, cancellation, and teardown operations",
			"source cleanup", target.File, strings.Join(cleanup, "\n"))
		if err != nil {
			return err
		}
		accesses[len(accesses)-1].facts = append(accesses[len(accesses)-1].facts, id)
		model.Accesses[len(model.Accesses)-1].StateIdentifiers = uniqueStrings(append(model.Accesses[len(model.Accesses)-1].StateIdentifiers, accesses[len(accesses)-1].relatedIdentifiers...))
	}
	if testDetail := sourceTestContext(report, snapshot); testDetail != "" {
		if _, err := d.recordSourceAction(ctx, report, persist, "InspectTest", report.InvestigationID,
			"inspect the indexed test and setup context named by the failure evidence",
			"source test context", "repository test context", testDetail); err != nil {
			return err
		}
	}
	if len(accesses) > 0 {
		model.SharedState = sharedSourceState(accesses)
		for _, access := range accesses {
			model.EvidenceIDs = append(model.EvidenceIDs, access.facts...)
		}
		for _, race := range report.RaceReports {
			for index, stack := range race.GoroutineCreationStacks {
				if len(stack) > 0 {
					model.GoroutineOwnership = append(model.GoroutineOwnership, fmt.Sprintf("CI observed goroutine creation stack %d beginning at %s:%d; source ownership remains to be verified", index+1, stack[0].File, stack[0].Line))
				}
			}
		}
		if len(model.SharedState) == 0 {
			model.MissingOrdering = append(model.MissingOrdering, "shared memory identity could not be resolved from the observed expressions")
		} else {
			model.MissingOrdering = append(model.MissingOrdering, "no verified happens-before edge was established between the conflicting accesses")
		}
		if containsSourceToken(model.Synchronization, "Add") && containsSourceToken(model.Synchronization, "Wait") {
			model.MissingOrdering = append(model.MissingOrdering, "WaitGroup Add/Wait operations were found, but source inspection did not prove that every Add occurs before shutdown Wait")
		}
		if containsSourceToken(model.Synchronization, "close(") && containsSourceToken(model.Synchronization, "<-") {
			model.HappensBefore = append(model.HappensBefore, "source contains a channel close and a receive operation; Go channel semantics establish close-before-receive ordering for that channel")
		}
		model.EvidenceIDs = uniqueStrings(model.EvidenceIDs)
		report.Concurrency = model
		evaluateInvestigationObjectives(report)
	}

	if len(accesses) >= 2 && hasRaceIncident(report.FailureIncidents) {
		if hypothesis := sourceRaceHypothesis(report, accesses); hypothesis != nil {
			report.Hypotheses = append(report.Hypotheses, *hypothesis)
			if persist {
				if err := d.cfg.Store.SaveHypothesis(*hypothesis); err != nil {
					return err
				}
				if err := d.cfg.Store.SaveHypothesisHistory(domain.HypothesisHistory{ID: domain.NewID(), HypothesisID: hypothesis.ID, InvestigationID: hypothesis.InvestigationID, PreviousStatus: domain.HypProposed, NextStatus: domain.HypProposed, Evaluation: "bounded source investigation", CreatedAt: time.Now().UTC()}); err != nil {
					return err
				}
			}
		}
	}
	evaluateInvestigationObjectives(report)
	assignInvestigationTargets(report, snapshot)
	if persist {
		if err := d.saveInvestigationCheckpoint(report); err != nil {
			return err
		}
	}
	finishInvestigationObjective(report)
	return nil
}

// assignInvestigationTargets converts each unresolved dependency into a
// concrete source request. It uses only source facts already collected by the
// deterministic investigation; it does not infer a causal conclusion.
func assignInvestigationTargets(report *Report, snapshot programrepo.Snapshot) {
	if report.InvestigationObjective == nil {
		return
	}
	for i := range report.InvestigationObjective.Unknowns {
		u := &report.InvestigationObjective.Unknowns[i]
		var target string
		switch u.ID {
		case "exact-memory":
			u.TargetSymbol, target = accessTarget(report, snapshot, 0)
		case "goroutine-ownership":
			u.TargetSymbol, target = accessRelatedTarget(report, snapshot, 0)
		case "shutdown-ordering", "happens-before":
			u.TargetSymbol, target = accessRelatedTarget(report, snapshot, 1)
		}
		if u.ID == "exact-memory" && u.TargetSymbol == "" && report.Concurrency != nil && len(report.Concurrency.Accesses) > 0 {
			a := report.Concurrency.Accesses[0]
			u.TargetSymbol, target = a.Function, fmt.Sprintf("%s:%d:%s", a.File, a.Line, a.Function)
		}
		u.Target = target
	}
}

func accessTarget(report *Report, snapshot programrepo.Snapshot, index int) (string, string) {
	if report.Concurrency == nil || len(report.Concurrency.Accesses) <= index {
		return "", ""
	}
	a := report.Concurrency.Accesses[index]
	return a.Function, fmt.Sprintf("%s:%d:%s", a.File, a.Line, a.Function)
}

func accessRelatedTarget(report *Report, snapshot programrepo.Snapshot, index int) (string, string) {
	if report.Concurrency == nil || len(report.Concurrency.Accesses) <= index {
		return "", ""
	}
	a := report.Concurrency.Accesses[index]
	node := enclosingSourceNode(snapshot.Nodes, a.File, a.Line)
	if node == nil {
		return "", ""
	}
	for _, relation := range snapshot.Relationships {
		if relation.Type != "CALLS" || relation.SourceID != node.ID || relation.Metadata["provenance"] != "verified_static_call" {
			continue
		}
		for _, candidate := range snapshot.Nodes {
			if candidate.ID == relation.TargetID && (candidate.Type == "Function" || candidate.Type == "Method") {
				return candidate.Identity, fmt.Sprintf("%s:%d:%s", candidate.FilePath, candidate.StartLine, candidate.Identity)
			}
		}
	}
	return "", ""
}

func (d *Diagnoser) recordSourceAction(ctx context.Context, report *Report, persist bool, actionType, target, summary, kind, source, detail string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if len(report.InvestigationActions) >= 24 {
		return "", nil
	}
	if detail == "" {
		return "", nil
	}
	hash := sha256.Sum256([]byte(report.InvestigationID + "\x00" + actionType + "\x00" + target + "\x00" + detail))
	digest := hex.EncodeToString(hash[:])
	evidenceID := "E-investigation-" + digest[:12]
	evidence := EvidenceItem{ID: evidenceID, Kind: kind, ClaimKind: kind, Basis: "SourceVerified", Source: source, Digest: digest, Detail: detail, Provenance: "deterministic source inspection of checked-out revision", Revision: report.Environment.HeadCommit, DeclarationID: target}
	report.Evidence = append(report.Evidence, evidence)
	status := sourceActionStatus(detail)
	action := InvestigationAction{ID: "action:" + digest[:16], Type: actionType, Target: target, Status: status, Summary: summary, EvidenceIDs: []string{evidenceID}, UnknownIDs: sourceUnknownsForAction(actionType), Revision: report.Environment.HeadCommit}
	action.Result = sourceActionResult(actionType, status, detail)
	report.InvestigationActions = append(report.InvestigationActions, action)
	applyInvestigationAction(report, action)
	if !persist {
		return evidenceID, nil
	}
	if d.cfg.Store == nil {
		return evidenceID, nil
	}
	if err := d.cfg.Store.SaveEvidence(domain.Evidence{ID: domain.ID(evidenceID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceSourceCode, Source: source, Timestamp: report.CreatedAt, ContentRef: kind, Digest: digest, Payload: detail, Provenance: evidence.Provenance, ClaimKind: evidence.ClaimKind, Basis: evidence.Basis, DeclarationID: evidence.DeclarationID, Revision: evidence.Revision}); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	activityStatus := domain.ActivityCompleted
	if status == "partial" {
		activityStatus = domain.ActivityPartial
	}
	activity := domain.Activity{ID: action.ID, InvestigationID: domain.ID(report.InvestigationID), Type: actionType, Status: activityStatus, InputRefs: []string{target}, OutputRefs: []string{evidenceID}, AttemptCount: 1, SelectionReason: "source investigation selected from localized failure evidence", StartedAt: &now, CompletedAt: &now}
	if err := d.cfg.Store.SaveActivity(activity); err != nil {
		return "", err
	}
	// Checkpoint after each meaningful action. The activity/evidence rows and
	// this derived objective state are written before the next action begins.
	if err := d.saveInvestigationCheckpoint(report); err != nil {
		return "", err
	}
	return evidenceID, nil
}

func beginInvestigationObjective(report *Report) {
	if report.InvestigationObjective != nil {
		return
	}
	objective := "Explain the observed CI failure from source-backed facts and determine whether a causal mechanism is established."
	unknowns := []InvestigationUnknown{
		{ID: "exact-memory", Question: "What exact expression and shared memory identity did each conflicting access use?", Predicate: "source function plus variable/reference facts identify the same concrete state for both accesses", RequiredKinds: []string{"source function", "source variable trace", "source references"}, Requirements: []EvidenceRequirement{{ClaimKind: "source function", MinimumBasis: "SourceVerified"}, {ClaimKind: "source variable trace", MinimumBasis: "SourceVerified"}, {ClaimKind: "source references", MinimumBasis: "SourceVerified"}, {ClaimKind: "same-runtime-instance", MinimumBasis: "RuntimeObserved", SameInstance: true}}, CandidateActions: []string{"InspectFunction", "TraceVariable", "FindReferences"}, NextAction: "TraceVariable", Revision: report.Environment.HeadCommit},
		{ID: "goroutine-ownership", Question: "Which goroutine owns each access, and how is its lifecycle terminated?", Predicate: "lifecycle and cleanup facts identify creation, execution, cancellation, completion, and ownership without unresolved edges", RequiredKinds: []string{"source lifecycle", "source cleanup"}, Requirements: []EvidenceRequirement{{ClaimKind: "source lifecycle", MinimumBasis: "SourceVerified"}, {ClaimKind: "source cleanup", MinimumBasis: "SourceVerified"}}, CandidateActions: []string{"InspectFunction", "InspectGoroutineLifecycle", "InspectCleanup"}, NextAction: "InspectGoroutineLifecycle", Revision: report.Environment.HeadCommit},
		{ID: "shutdown-ordering", Question: "Does shutdown wait for the background goroutine before it can overlap the access?", Predicate: "source facts establish registration-before-wait and completion-before-shutdown for the relevant goroutine", RequiredKinds: []string{"source lifecycle", "source cleanup", "source synchronization"}, Requirements: []EvidenceRequirement{{ClaimKind: "source lifecycle", MinimumBasis: "SourceVerified"}, {ClaimKind: "source cleanup", MinimumBasis: "SourceVerified"}, {ClaimKind: "synchronization-ordering", MinimumBasis: "SourceVerified", Ordering: "happens-before"}}, CandidateActions: []string{"InspectGoroutineLifecycle", "InspectCleanup", "InspectSynchronization"}, NextAction: "InspectSynchronization", Revision: report.Environment.HeadCommit},
		{ID: "happens-before", Question: "What verified synchronization or happens-before edge orders the two accesses?", Predicate: "a synchronization fact explicitly establishes an edge between the exact conflicting accesses", RequiredKinds: []string{"source synchronization"}, Requirements: []EvidenceRequirement{{ClaimKind: "synchronization-ordering", MinimumBasis: "SourceVerified", Ordering: "happens-before"}}, CandidateActions: []string{"InspectSynchronization", "TraceCallers", "TraceCallees"}, NextAction: "InspectSynchronization", Revision: report.Environment.HeadCommit},
	}
	if !hasRaceIncident(report.FailureIncidents) && len(report.RaceReports) == 0 {
		objective = "Explain the observed CI failure from source-backed facts and identify the missing mechanism or verification needed for a causal diagnosis."
		unknowns = unknowns[:1]
	}
	for i := range unknowns {
		unknowns[i].Status = "unresolved"
	}
	report.InvestigationObjective = &InvestigationObjective{FailureObjective: objective, Unknowns: unknowns, Status: "investigating"}
}

func sourceUnknownsForAction(actionType string) []string {
	switch actionType {
	case "TraceVariable", "FindReferences":
		return []string{"exact-memory"}
	case "InspectGoroutineLifecycle":
		return []string{"goroutine-ownership", "shutdown-ordering"}
	case "InspectCleanup":
		return []string{"goroutine-ownership", "shutdown-ordering"}
	case "InspectSynchronization":
		return []string{"shutdown-ordering", "happens-before"}
	case "InspectFunction":
		return []string{"exact-memory", "goroutine-ownership"}
	case "TraceCallers", "TraceCallees":
		return []string{"happens-before"}
	default:
		return nil
	}
}

func sourceActionResult(actionType, status, detail string) string {
	if status != "completed" {
		return "partial: substantive evidence was collected, but the action did not resolve its assigned unknown"
	}
	if actionType == "InspectSynchronization" && !strings.Contains(strings.ToLower(detail), "verified") {
		return "evidence collected; synchronization was observed but not verified as a happens-before edge"
	}
	if strings.Contains(strings.ToLower(detail), "unresolved") || strings.Contains(strings.ToLower(detail), "not proof") || strings.Contains(strings.ToLower(detail), "no synchronization") {
		return "evidence collected; the assigned unknown remains unresolved"
	}
	return "evidence collected for the assigned unknown"
}

func applyInvestigationAction(report *Report, action InvestigationAction) {
	if report.InvestigationObjective == nil {
		return
	}
	for _, unknownID := range action.UnknownIDs {
		for i := range report.InvestigationObjective.Unknowns {
			unknown := &report.InvestigationObjective.Unknowns[i]
			if unknown.ID != unknownID {
				continue
			}
			for _, evidenceID := range action.EvidenceIDs {
				unknown.EvidenceIDs = appendUniqueString(unknown.EvidenceIDs, evidenceID)
			}
			if unknown.Status != "resolved" && unknown.Status != "refuted" {
				unknown.Status = "investigating"
			}
			unknown.Evaluation = "action completed; objective predicate has not yet been evaluated"
		}
	}
	evaluateInvestigationObjectives(report)
	for index := range report.InvestigationActions {
		if report.InvestigationActions[index].ID != action.ID {
			continue
		}
		relevant := false
		for _, unknownID := range action.UnknownIDs {
			for _, unknown := range report.InvestigationObjective.Unknowns {
				if unknown.ID == unknownID {
					relevant = true
					report.InvestigationActions[index].Resolved = report.InvestigationActions[index].Resolved || unknown.Status == "resolved"
					report.InvestigationActions[index].Missing = append([]string(nil), unknown.MissingRequirements...)
				}
			}
		}
		report.InvestigationActions[index].Executed = true
		report.InvestigationActions[index].Advanced = relevant && (len(report.InvestigationActions[index].Missing) == 0 || report.InvestigationActions[index].Resolved)
	}
}

// evaluateInvestigationObjectives is deliberately conservative. It checks
// persisted source facts, not action status or the presence of a primitive.
// The synchronization predicates require an explicit verified edge, so a
// discovered WaitGroup/lock/channel remains unresolved until ordering is
// actually established.
func evaluateInvestigationObjectives(report *Report) {
	if report.InvestigationObjective == nil {
		return
	}
	for index := range report.InvestigationObjective.Unknowns {
		u := &report.InvestigationObjective.Unknowns[index]
		if u.Status == "rejected" || u.Status == "not_applicable" {
			continue
		}
		u.Status = "unresolved"
		u.Evaluation = "required evidence is missing, ambiguous, stale, or inferred"
		u.MissingRequirements = nil
		if u.Revision != "" && report.Environment.HeadCommit != "" && u.Revision != report.Environment.HeadCommit {
			u.Evaluation = "objective evidence belongs to a different source revision"
			continue
		}
		if len(u.Requirements) > 0 {
			result := evaluateStrictObjective(*u, report.Evidence, report.Environment.HeadCommit)
			for _, id := range result.EvidenceIDs {
				u.EvidenceIDs = appendUniqueString(u.EvidenceIDs, id)
			}
			u.MissingRequirements = result.Missing
			u.Evaluation = result.Evaluation
			if result.Resolved {
				for _, id := range result.EvidenceIDs {
					u.ResolutionIDs = appendUniqueString(u.ResolutionIDs, id)
				}
				u.Status = "resolved"
				u.NextAction = ""
			}
			continue
		}
		var matching []EvidenceItem
		for _, ev := range report.Evidence {
			if ev.Revision != "" && report.Environment.HeadCommit != "" && ev.Revision != report.Environment.HeadCommit {
				continue
			}
			for _, kind := range u.RequiredKinds {
				if ev.Kind == kind && !sourceDetailUnresolved(ev.Detail) {
					matching = append(matching, ev)
					break
				}
			}
		}
		if len(matching) < len(u.RequiredKinds) {
			continue
		}
		if u.ID == "exact-memory" {
			if report.Concurrency == nil || len(report.Concurrency.Accesses) < 2 {
				continue
			}
			left, right := report.Concurrency.Accesses[0], report.Concurrency.Accesses[1]
			if !left.ExactMemory || !right.ExactMemory || left.MemoryIdentity == "" || left.MemoryIdentity != right.MemoryIdentity {
				u.Evaluation = "source frames identify calls or wrappers, but do not establish one concrete memory object or field for both accesses"
				continue
			}
		}
		if u.ID == "goroutine-ownership" {
			if report.Concurrency == nil {
				continue
			}
			verifiedOwnership := true
			for _, owner := range report.Concurrency.GoroutineOwnership {
				if strings.Contains(strings.ToLower(owner), "remains to be verified") || strings.Contains(strings.ToLower(owner), "unresolved") {
					verifiedOwnership = false
				}
			}
			if !verifiedOwnership {
				u.Evaluation = "goroutine creation was observed, but ownership or completion edges remain unverified"
				continue
			}
			lifecycle, cleanup := false, false
			for _, ev := range matching {
				text := strings.ToLower(ev.Detail)
				if ev.Kind == "source lifecycle" && (strings.Contains(text, "goroutine") || strings.Contains(text, "go ") || strings.Contains(text, "wait")) {
					lifecycle = true
				}
				if ev.Kind == "source cleanup" && (strings.Contains(text, "close") || strings.Contains(text, "stop") || strings.Contains(text, "cleanup") || strings.Contains(text, "defer")) {
					cleanup = true
				}
			}
			if !lifecycle || !cleanup {
				continue
			}
		}
		if u.ID == "shutdown-ordering" || u.ID == "happens-before" {
			verified := false
			for _, ev := range matching {
				text := strings.ToLower(ev.Detail)
				if strings.Contains(text, "verified happens-before") || strings.Contains(text, "ordering established") || strings.Contains(text, "establishes an edge between") {
					verified = true
				}
			}
			if !verified {
				continue
			}
		}
		for _, ev := range matching {
			u.EvidenceIDs = appendUniqueString(u.EvidenceIDs, ev.ID)
			u.ResolutionIDs = appendUniqueString(u.ResolutionIDs, ev.ID)
		}
		u.Status = "resolved"
		u.Evaluation = "resolution predicate satisfied by revision-scoped evidence"
		u.NextAction = ""
	}
}

type objectiveEvaluation struct {
	Resolved    bool
	EvidenceIDs []string
	Missing     []string
	Evaluation  string
}

var evidenceBasisRank = map[string]int{"Observed": 1, "Inferred": 1, "SourceVerified": 2, "RuntimeObserved": 3, "Experimental": 4}

func evaluateStrictObjective(objective InvestigationUnknown, evidence []EvidenceItem, revision string) objectiveEvaluation {
	result := objectiveEvaluation{Evaluation: "required evidence is missing, unrelated, inferred, stale, or insufficiently proven"}
	for _, requirement := range objective.Requirements {
		found := false
		for _, item := range evidence {
			claim := item.ClaimKind
			if claim == "" {
				claim = item.Kind
			}
			if claim != requirement.ClaimKind || (revision != "" && item.Revision != "" && item.Revision != revision) {
				continue
			}
			if requirement.Subject != "" && requirement.Subject != item.DeclarationID && requirement.Subject != item.AccessID && requirement.Subject != item.InstanceID {
				continue
			}
			if evidenceBasisRank[item.Basis] < evidenceBasisRank[requirement.MinimumBasis] || item.Basis == "Inferred" {
				continue
			}
			if requirement.SameInstance && item.InstanceID == "" {
				continue
			}
			if requirement.Ordering != "" && item.Ordering != requirement.Ordering {
				continue
			}
			result.EvidenceIDs = appendUniqueString(result.EvidenceIDs, item.ID)
			found = true
			break
		}
		if !found {
			missing := requirement.ClaimKind
			if requirement.Subject != "" {
				missing += " for subject " + requirement.Subject
			}
			if requirement.Ordering != "" {
				missing += " (" + requirement.Ordering + ")"
			}
			result.Missing = append(result.Missing, missing)
		}
	}
	if len(result.Missing) == 0 {
		result.Resolved = true
		result.Evaluation = "typed objective requirements satisfied by qualifying evidence"
	} else {
		result.Evaluation = "missing qualifying evidence: " + strings.Join(result.Missing, "; ")
	}
	return result
}

func sourceDetailUnresolved(detail string) bool {
	text := strings.ToLower(detail)
	for _, marker := range []string{"unresolved", "not proof", "no explicit", "no synchronization", "could not be resolved", "remains to be verified"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func (d *Diagnoser) saveInvestigationCheckpoint(report *Report) error {
	if d.cfg.Store == nil || report.InvestigationObjective == nil {
		return nil
	}
	objectives := make([]domain.AdaptiveObjective, 0, len(report.InvestigationObjective.Unknowns))
	for _, u := range report.InvestigationObjective.Unknowns {
		objectives = append(objectives, domain.AdaptiveObjective{ID: u.ID, Question: u.Question, Predicate: u.Predicate, Status: u.Status, EvidenceIDs: stringIDsToDomain(u.EvidenceIDs), ResolutionEvidence: stringIDsToDomain(u.ResolutionIDs), Evaluation: u.Evaluation, Revision: u.Revision, NextAction: u.NextAction, CandidateActions: append([]string(nil), u.CandidateActions...), RequiredEvidence: append([]string(nil), u.RequiredKinds...), Requirements: domainRequirements(u.Requirements), MissingRequirements: append([]string(nil), u.MissingRequirements...), RefutedBy: stringIDsToDomain(u.RefutedBy), Target: u.Target, TargetSymbol: u.TargetSymbol})
	}
	state, err := d.cfg.Store.GetAdaptiveState(domain.ID(report.InvestigationID))
	if err != nil {
		state = domain.AdaptiveState{InvestigationID: domain.ID(report.InvestigationID)}
	}
	state.Objectives = objectives
	state.UpdatedAt = time.Now().UTC()
	return d.cfg.Store.SaveAdaptiveState(state)
}

func domainRequirements(values []EvidenceRequirement) []domain.EvidenceRequirement {
	out := make([]domain.EvidenceRequirement, 0, len(values))
	for _, value := range values {
		out = append(out, domain.EvidenceRequirement{ClaimKind: value.ClaimKind, Subject: value.Subject, MinimumBasis: value.MinimumBasis, Revision: value.Revision, SameInstance: value.SameInstance, Ordering: value.Ordering})
	}
	return out
}

func finishInvestigationObjective(report *Report) {
	if report.InvestigationObjective == nil {
		return
	}
	remaining := make([]string, 0)
	for i := range report.InvestigationObjective.Unknowns {
		unknown := &report.InvestigationObjective.Unknowns[i]
		if unknown.Status != "resolved" {
			remaining = append(remaining, unknown.ID)
		}
	}
	if len(remaining) == 0 {
		report.InvestigationObjective.Status = "causal_review_required"
		report.InvestigationObjective.StoppingReason = "all planned source unknowns have evidence; causal explanation still requires hypothesis evaluation"
		return
	}
	// Source retrieval is only one stage. Leave the objective active so the
	// adaptive controller can choose a runtime or discriminating follow-up.
	report.InvestigationObjective.Status = "investigating"
	report.InvestigationObjective.StoppingReason = "source evidence did not yet resolve: " + strings.Join(remaining, ", ")
}

func sourceActionStatus(detail string) string {
	partialMarkers := []string{"not proof", "unresolved", "no matching", "no explicit", "no synchronization"}
	for _, marker := range partialMarkers {
		if strings.Contains(strings.ToLower(detail), marker) {
			return "partial"
		}
	}
	return "completed"
}

func sourceInvestigationTargets(report *Report, candidates []domain.CandidateLocation) []sourceAccessTarget {
	var targets []sourceAccessTarget
	seen := map[string]bool{}
	add := func(access, file string, line int, address, role string) {
		file = filepath.ToSlash(strings.TrimSpace(file))
		if file == "" || line <= 0 || filepath.IsAbs(file) || strings.HasPrefix(file, "../") {
			return
		}
		if role == "" {
			role = "enclosing_source_frame"
		}
		key := access + "\x00" + file + ":" + fmt.Sprint(line)
		if !seen[key] {
			seen[key] = true
			targets = append(targets, sourceAccessTarget{Access: access, File: file, Line: line, Address: address, FrameRole: role, ExactSource: role == "enclosing_source_frame"})
		}
	}
	for _, race := range report.RaceReports {
		if len(race.ReadStack) > 0 {
			add("read", race.ReadStack[0].File, race.ReadStack[0].Line, race.ReadAddress, race.ReadFrameRole)
		}
		if len(race.WriteStack) > 0 {
			add("write", race.WriteStack[0].File, race.WriteStack[0].Line, race.WriteAddress, race.WriteFrameRole)
		}
	}
	if len(targets) == 0 {
		for _, candidate := range candidates {
			if candidate.Location.Provenance == "direct_stack_frame" || candidate.Location.Provenance == "observed_frame" {
				add("observed", candidate.Location.FilePath, candidate.Location.StartLine, "", "enclosing_source_frame")
			}
			if len(targets) >= 4 {
				break
			}
		}
	}
	return targets
}

func enclosingSourceNode(nodes []domain.ProgramNode, file string, line int) *domain.ProgramNode {
	var best *domain.ProgramNode
	for index := range nodes {
		node := &nodes[index]
		if node.FilePath != file || (node.Type != "Function" && node.Type != "Method" && node.Type != "Test") || node.StartLine > line || node.EndLine < line {
			continue
		}
		if best == nil || (node.EndLine-node.StartLine) < (best.EndLine-best.StartLine) {
			best = node
		}
	}
	return best
}

func numberedSource(lines []string, start, end int) string {
	var b strings.Builder
	for line := start; line <= end; line++ {
		fmt.Fprintf(&b, "%d| %s\n", line, lines[line-1])
	}
	return b.String()
}

func sourceVariables(line string) []string {
	keywords := map[string]bool{"if": true, "else": true, "for": true, "range": true, "return": true, "go": true, "defer": true, "func": true, "var": true, "const": true, "type": true, "nil": true, "true": true, "false": true, "package": true, "select": true, "case": true, "default": true}
	seen := map[string]bool{}
	var result []string
	for _, value := range sourceIdentifierRE.FindAllString(line, -1) {
		if keywords[value] || seen[value] || len(value) < 2 {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func sourceStateIdentifiers(text string) []string {
	values := sourceVariables(text)
	values = append(values, sourceFieldRE.FindAllString(text, -1)...)
	return uniqueStrings(values)
}

func traceVariables(lines []string, variables []string) []string {
	var out []string
	for _, variable := range variables {
		pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(variable) + `\b`)
		count := 0
		for index, line := range lines {
			if pattern.MatchString(line) {
				out = append(out, fmt.Sprintf("%d| %s", index+1, line))
				count++
				if count >= 8 {
					break
				}
			}
		}
	}
	return out
}

func referenceLines(lines []string, variables []string) []string {
	refs := traceVariables(lines, variables)
	if len(refs) > 24 {
		return refs[:24]
	}
	return refs
}

func synchronizationLines(lines []string, start, end int) []string {
	patterns := []*regexp.Regexp{regexp.MustCompile(`\b(Lock|RLock|Unlock|RUnlock|Wait|Done|Add|close)\s*\(`), regexp.MustCompile(`\batomic\.`), regexp.MustCompile(`\b(chan|select)\b`), regexp.MustCompile(`<-[[:space:]]*[A-Za-z_]`)}
	var result []string
	for line := start; line <= end && line <= len(lines); line++ {
		for _, pattern := range patterns {
			if pattern.MatchString(lines[line-1]) {
				result = append(result, fmt.Sprintf("%d| %s", line, lines[line-1]))
				break
			}
		}
	}
	return result
}

func lifecycleLines(lines []string, start, end int) []string {
	pattern := regexp.MustCompile(`\bgo\s+|\bcontext\.|\bcancel\s*\(|\bWait\s*\(|\bClose\s*\(|\bdefer\b`)
	var result []string
	for line := start; line <= end && line <= len(lines); line++ {
		if pattern.MatchString(lines[line-1]) {
			result = append(result, fmt.Sprintf("%d| %s", line, lines[line-1]))
		}
	}
	return result
}

func cleanupLines(lines []string, start, end int) []string {
	pattern := regexp.MustCompile(`\bdefer\b|\b(Close|cancel|Cleanup|TearDown|Stop|Shutdown)\s*\(`)
	var result []string
	for line := start; line <= end && line <= len(lines); line++ {
		if pattern.MatchString(lines[line-1]) {
			result = append(result, fmt.Sprintf("%d| %s", line, lines[line-1]))
		}
	}
	return result
}

func relatedCallFacts(relations []domain.Relationship, nodeID string, nodes []domain.ProgramNode) []string {
	byID := map[string]domain.ProgramNode{}
	for _, node := range nodes {
		byID[node.ID] = node
	}
	var result []string
	for _, relation := range relations {
		if relation.Type != "CALLS" || (relation.SourceID != nodeID && relation.TargetID != nodeID) || relation.Metadata["provenance"] != "verified_static_call" {
			continue
		}
		source, sourceOK := byID[relation.SourceID]
		target, targetOK := byID[relation.TargetID]
		if sourceOK && targetOK {
			result = append(result, fmt.Sprintf("%s -> %s [verified_static_call]", source.Identity, target.Identity))
		}
	}
	sort.Strings(result)
	return result
}

func goAccessExpression(path string, line int) string {
	data, err := os.ReadFile(path)
	if err != nil || filepath.Ext(path) != ".go" {
		return ""
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, parser.ParseComments)
	if err != nil {
		return ""
	}
	var best ast.Node
	bestWidth := int(^uint(0) >> 1)
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			return false
		}
		start := fset.Position(node.Pos()).Line
		end := fset.Position(node.End()).Line
		if start > line || end < line {
			return true
		}
		switch node.(type) {
		case *ast.GoStmt, *ast.CallExpr, *ast.AssignStmt, *ast.SelectorExpr, *ast.IndexExpr, *ast.UnaryExpr:
			width := end - start
			if width < bestWidth {
				best, bestWidth = node, width
			}
		}
		return true
	})
	if best == nil {
		return ""
	}
	var out bytes.Buffer
	if err := format.Node(&out, fset, best); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}

func relatedSourceNodes(snapshot programrepo.Snapshot, node *domain.ProgramNode, expression string) []domain.ProgramNode {
	names := sourceVariables(expression)
	byName := map[string][]domain.ProgramNode{}
	for _, candidate := range snapshot.Nodes {
		if candidate.ID == node.ID || (candidate.Type != "Function" && candidate.Type != "Method" && candidate.Type != "Test") {
			continue
		}
		byName[candidate.Name] = append(byName[candidate.Name], candidate)
	}
	seen := map[string]bool{}
	var related []domain.ProgramNode
	for _, name := range names {
		for _, candidate := range byName[name] {
			if filepath.Dir(candidate.FilePath) != filepath.Dir(node.FilePath) || seen[candidate.ID] {
				continue
			}
			seen[candidate.ID] = true
			related = append(related, candidate)
			if len(related) >= 6 {
				return related
			}
		}
	}
	sort.Slice(related, func(i, j int) bool { return related[i].Identity < related[j].Identity })
	return related
}

// relatedImplementationNodes follows resolved static call edges in addition
// to same-package name matches. This is what lets a cleanup call such as
// rawCacher.Stop() reach the actual Cacher.Stop implementation without
// presenting the call site itself as the implementation or memory access.
func relatedImplementationNodes(snapshot programrepo.Snapshot, node *domain.ProgramNode, expression string) []domain.ProgramNode {
	result := relatedSourceNodes(snapshot, node, expression)
	seen := map[string]bool{node.ID: true}
	for _, value := range result {
		seen[value.ID] = true
	}
	method := ""
	if dot := strings.LastIndex(expression, "."); dot >= 0 {
		method = strings.TrimSuffix(strings.TrimSpace(expression[dot+1:]), "()")
	}
	for _, relation := range snapshot.Relationships {
		if relation.Type != "CALLS" || relation.SourceID != node.ID || relation.Metadata["provenance"] != "verified_static_call" {
			continue
		}
		for _, candidate := range snapshot.Nodes {
			if candidate.ID != relation.TargetID || seen[candidate.ID] || (method != "" && candidate.Name != method) {
				continue
			}
			if candidate.Type == "Function" || candidate.Type == "Method" {
				result = append(result, candidate)
				seen[candidate.ID] = true
			}
		}
	}
	if method != "" {
		matches := 0
		for _, candidate := range snapshot.Nodes {
			if seen[candidate.ID] || candidate.Type != "Method" || candidate.Name != method {
				continue
			}
			// A name-only fallback is explicitly an unresolved candidate set,
			// not proof of dispatch. It ensures cleanup implementations such as
			// Stop are inspected when the index lacks a typed call edge.
			result = append(result, candidate)
			seen[candidate.ID] = true
			matches++
			if matches >= 6 {
				break
			}
		}
	}
	return result
}

func sharedSourceState(accesses []sourceAccessObservation) []string {
	if len(accesses) < 2 {
		return nil
	}
	// Identifier overlap is not an alias proof. Only an independently
	// resolved source identity can enter the concurrency model as shared state.
	seen := map[string]bool{}
	for _, access := range accesses {
		if !access.exactMemory || access.memoryIdentity == "" {
			return nil
		}
	}
	if accesses[0].memoryIdentity == accesses[1].memoryIdentity {
		seen[accesses[0].memoryIdentity] = true
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sourceMemoryIdentity(path string, line int, expression string) (bool, string) {
	text := strings.TrimSpace(expression)
	if text == "" || strings.HasPrefix(text, "go ") || strings.Contains(text, "(") {
		return false, ""
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "return "))
	if index := strings.Index(text, "="); index >= 0 {
		text = strings.TrimSpace(strings.TrimPrefix(text[:index], "*"))
	}
	if text == "" || !sourceIdentifierRE.MatchString(text) || strings.ContainsAny(text, " +-*/!<>[]") {
		return false, ""
	}
	// The source line is part of the identity provenance; the current
	// identity is intentionally conservative and does not infer pointer aliasing.
	if _, err := os.Stat(path); err != nil || line <= 0 {
		return false, ""
	}
	return true, text
}

func sourceTestContext(report *Report, snapshot programrepo.Snapshot) string {
	var tests []string
	for _, race := range report.RaceReports {
		if race.Test != "" {
			tests = append(tests, race.Test)
		}
	}
	if len(tests) == 0 {
		return ""
	}
	var lines []string
	for _, node := range snapshot.Nodes {
		if node.Type != "Test" {
			continue
		}
		for _, test := range tests {
			if strings.Contains(test, node.Name) || strings.Contains(node.Name, test) {
				lines = append(lines, fmt.Sprintf("indexed test %s at %s:%d-%d", node.Identity, node.FilePath, node.StartLine, node.EndLine))
			}
		}
	}
	if len(lines) == 0 {
		return "test identifier from CI: " + strings.Join(tests, "; ") + "\nno matching test symbol was indexed; test setup context remains unresolved"
	}
	sort.Strings(lines)
	return "test identifiers from CI: " + strings.Join(tests, "; ") + "\n" + strings.Join(lines, "\n")
}

func sourceRaceHypothesis(report *Report, accesses []sourceAccessObservation) *domain.Hypothesis {
	shared := sharedSourceState(accesses)
	if len(shared) == 0 {
		return nil
	}
	contradicting := []string{}
	for _, access := range accesses {
		if access.synchronizationEvidenceID != "" {
			contradicting = append(contradicting, access.synchronizationEvidenceID)
		}
	}
	if len(contradicting) == 0 {
		return nil
	}
	variables := shared
	supporting := append([]string{}, accesses[0].facts...)
	supporting = append(supporting, accesses[1].facts...)
	idBytes := sha256.Sum256([]byte(report.InvestigationID + "\x00" + strings.Join(variables, ",")))
	return &domain.Hypothesis{
		ID:                       domain.ID("hypothesis:source-race:" + hex.EncodeToString(idBytes[:8])),
		InvestigationID:          domain.ID(report.InvestigationID),
		Statement:                fmt.Sprintf("The conflicting %s and %s accesses both reference %s; they may execute without a verified happens-before edge, but source inspection has not established the violated ownership or synchronization invariant.", accesses[0].target.Access, accesses[1].target.Access, strings.Join(variables, ", ")),
		AffectedComponent:        accesses[0].target.File + " and " + accesses[1].target.File,
		SupportingEvidenceIDs:    stringIDsToDomain(uniqueStrings(supporting)),
		ContradictingEvidenceIDs: stringIDsToDomain(uniqueStrings(contradicting)),
		PredictedObservations:    []string{"a source or targeted experiment that demonstrates lock, channel, atomic, or lifecycle ordering between both accesses would distinguish this hypothesis from a benign synchronization path"},
		Invariant:                "every goroutine accessing the shared state must be ordered by a verified ownership or happens-before relationship",
		Confidence:               0.35,
		Status:                   domain.HypProposed,
		Relevance:                0.35,
		MissingEvidence:          []string{"verified happens-before or ownership ordering between both accesses", "a controlled experiment that distinguishes synchronization failure from benign concurrent access"},
		Provenance:               "deterministic source investigation",
	}
}

// raceHypotheses creates competing mechanisms, never candidate-location
// claims. Each statement remains conditional until exact memory identity and
// lifecycle/order evidence satisfy its missing requirements.
func raceHypotheses(report *Report) []domain.Hypothesis {
	var support []domain.ID
	for _, incident := range report.FailureIncidents {
		if incident.Category == "go_data_race" {
			support = append(support, stringIDsToDomain(incident.EvidenceIDs)...)
		}
	}
	if report.Concurrency != nil {
		support = append(support, stringIDsToDomain(report.Concurrency.EvidenceIDs)...)
	}
	support = uniqueDomainIDs(support)
	return []domain.Hypothesis{
		{ID: domain.ID("hypothesis:race:lifecycle-ordering:" + report.InvestigationID), InvestigationID: domain.ID(report.InvestigationID), Statement: "The observed race is caused by a background goroutine accessing cacher-owned state after teardown begins because the relevant lifecycle completion is not ordered before cleanup.", Invariant: "A goroutine must complete before teardown releases or mutates the state it can access.", AffectedComponent: "cacher lifecycle", SupportingEvidenceIDs: support, PredictedObservations: []string{"The exact read and write resolve to the same object or field and the Stop path lacks a verified completion-before-cleanup edge."}, MissingEvidence: []string{"exact source-level memory identity", "verified lifecycle ordering or its absence"}, Confidence: 0.3, Status: domain.HypProposed, Provenance: "race evidence plus deterministic source facts", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		{ID: domain.ID("hypothesis:race:distinct-state:" + report.InvestigationID), InvestigationID: domain.ID(report.InvestigationID), Statement: "The race report's wrapper and cleanup frames do not identify the same source-level object; the apparent lifecycle relationship may be incidental and the conflicting accesses may belong to distinct state or an unresolved alias.", Invariant: "A race explanation requires proof that both accesses reach the same concrete memory object or field.", AffectedComponent: "unresolved source memory", SupportingEvidenceIDs: support, PredictedObservations: []string{"Source-level analysis fails to resolve one concrete identity or establishes different identities for the two access expressions."}, MissingEvidence: []string{"concrete memory identity and alias relationship"}, Confidence: 0.3, Status: domain.HypProposed, Provenance: "race frame semantics", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
	}
}

func uniqueDomainIDs(values []domain.ID) []domain.ID {
	seen := map[domain.ID]bool{}
	out := make([]domain.ID, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func containsSourceToken(values []string, token string) bool {
	for _, value := range values {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
