package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/registry"
)

// runList prints the registry: JSON by default, the docs table with -doc.
func runList(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	doc := fs.Bool("doc", false, "print the Markdown table docs/harness-design.md carries")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	all, err := registry.Scan(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *doc {
		fmt.Fprint(stdout, registry.DocTable(all))
		return 0
	}
	type row struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Tier    string   `json:"tier"`
		Needs   []string `json:"needs"`
		Timeout string   `json:"timeout"`
		Package string   `json:"package"`
		Test    string   `json:"test"`
	}
	var rows []row
	for _, e := range all {
		r := row{ID: e.ID, Name: e.Name, Tier: string(e.Tier), Timeout: e.Timeout.String(), Package: e.Package, Test: e.Test}
		for _, n := range e.Needs {
			r.Needs = append(r.Needs, string(n))
		}
		rows = append(rows, r)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rows); err != nil {
		return 1
	}
	return 0
}

// plan is what `harness run` will do, decided before anything runs.
type plan struct {
	label    string
	sel      []registry.Entry
	provided []registry.Need
	test     registry.GoTest
	results  string
}

// planRun turns the flags into a plan. With -id the caller asked for those scenarios by name, so
// the run promises every need they have; with -tier it promises what the tier provides.
func planRun(tier string, ids []string, resultsDir string, getenv func(string) string) (plan, error) {
	all, err := registry.Scan(".")
	if err != nil {
		return plan{}, err
	}
	var p plan
	if len(ids) > 0 {
		p.label = strings.Join(ids, ",")
		if p.sel, err = registry.Select(all, "", ids); err != nil {
			return plan{}, err
		}
		for _, e := range p.sel {
			for _, n := range e.Needs {
				if !slices.Contains(p.provided, n) {
					p.provided = append(p.provided, n)
				}
			}
		}
	} else {
		p.label = tier
		if p.sel, err = registry.Select(all, registry.Tier(tier), nil); err != nil {
			return plan{}, err
		}
		p.provided = registry.Provides(registry.Tier(tier), getenv)
	}
	if len(p.sel) == 0 {
		return plan{}, fmt.Errorf("nothing to run for %s", p.label)
	}
	p.test = registry.GoTestFor(p.sel)
	p.results = resultsDir
	return p, nil
}

// runTier runs a tier (or named scenarios) with `go test`, then judges the results: a scenario the
// tier promised must PASS, and one it did not promise is named with what it needed.
func runTier(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	tier := fs.String("tier", "", "fabric, pr or nightly")
	ids := fs.String("id", "", "comma-separated scenario ids, instead of a tier")
	results := fs.String("results", "", "directory for the results (default: a fresh temporary directory)")
	dry := fs.Bool("n", false, "print what would run, and what the tier promises, then stop")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*tier == "") == (*ids == "") {
		fmt.Fprintln(os.Stderr, "harness run: give exactly one of -tier or -id")
		return 2
	}
	dir := *results
	if *dry {
		dir = "(none: -n)"
	} else if dir == "" {
		d, err := os.MkdirTemp("", "pact-harness-results-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		dir = d
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var idList []string
	if *ids != "" {
		idList = strings.Split(*ids, ",")
	}
	p, err := planRun(*tier, idList, dir, os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness run:", err)
		return 2
	}
	printPlan(stdout, p)
	if *dry {
		return 0
	}
	// A result left in the directory by an earlier run must not answer for this one.
	for _, e := range p.sel {
		_ = os.Remove(filepath.Join(dir, e.ID+".json"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd := exec.CommandContext(ctx, "go", p.test.Args()...)
	cmd.Stdout, cmd.Stderr = stdout, os.Stderr
	cmd.Env = append(os.Environ(), registry.LiveEnv+"=1", registry.ResultsEnv+"="+dir)
	testErr := cmd.Run()

	code, err := judge(stdout, p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness run:", err)
		return 1
	}
	if testErr != nil {
		fmt.Fprintf(stdout, "harness: go test failed (%v)\n", testErr)
		code = 1
	}
	return code
}

func printPlan(w io.Writer, p plan) {
	fmt.Fprintf(w, "harness: %s — %d scenario(s), results in %s\n", p.label, len(p.sel), p.results)
	for _, e := range p.sel {
		if m := e.Missing(p.provided); len(m) > 0 {
			var how []string
			for _, n := range m {
				how = append(how, string(n)+": "+registry.HowToProvide(n))
			}
			fmt.Fprintf(w, "  NOT PROMISED %-4s %s\n               needs %s\n", e.ID, e.Name, strings.Join(how, "; "))
		} else {
			fmt.Fprintf(w, "  promised     %-4s %s\n", e.ID, e.Name)
		}
	}
	fmt.Fprintf(w, "harness: go %s\n", strings.Join(p.test.Args(), " "))
}

// judge reads the results, prints the verdicts, writes summary.json, and returns the exit code.
func judge(w io.Writer, p plan) (int, error) {
	res, err := registry.ReadResults(p.results)
	if err != nil {
		return 1, err
	}
	cases := registry.Judge(p.sel, p.provided, res)
	fmt.Fprintf(w, "\nharness: %s verdicts\n%s", p.label, registry.TableText(cases))
	sum := registry.Summary{Run: time.Now().UTC().Format(time.RFC3339), Repo: "pact-gateway", Tier: p.label, Cases: cases}
	b, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return 1, err
	}
	if err := os.WriteFile(filepath.Join(p.results, registry.SummaryFile), append(b, '\n'), 0o644); err != nil {
		return 1, err
	}
	if !registry.Passed(cases) {
		fmt.Fprintf(w, "harness: %s FAILED — a promised scenario did not pass (!! above)\n", p.label)
		return 1, nil
	}
	fmt.Fprintf(w, "harness: %s passed\n", p.label)
	return 0, nil
}
