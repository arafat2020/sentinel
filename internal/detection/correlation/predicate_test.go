package correlation

import (
	"strings"
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

func sp(s string) *string { return &s }

// textCase checks a string or address predicate against a present value that
// should match, one that should not, and a missing value.
type textCase struct {
	name      string
	predicate Predicate
	kind      fieldKind
	match     string
	noMatch   string
	// missing is the expected result for a missing (empty) value.
	missing bool
}

func TestStringAndAddressOperators(t *testing.T) {
	cases := []textCase{
		{name: "eq", predicate: Predicate{Eq: sp("python")}, match: "python", noMatch: "python3"},
		{name: "eq is case-sensitive", predicate: Predicate{Eq: sp("python")}, match: "python", noMatch: "Python"},
		{name: "eq nocase", predicate: Predicate{Eq: sp("python"), NoCase: true}, match: "PyThOn", noMatch: "pythons"},
		{name: "eq empty matches only a missing value", predicate: Predicate{Eq: sp("")}, match: "", noMatch: "x", missing: true},

		{name: "in", predicate: Predicate{In: []string{"bash", "sh", "zsh"}}, match: "sh", noMatch: "fish"},
		{name: "in nocase", predicate: Predicate{In: []string{"bash", "sh"}, NoCase: true}, match: "BASH", noMatch: "ash"},
		{name: "in with an empty entry still excludes missing", predicate: Predicate{In: []string{"", "sh"}}, match: "sh", noMatch: "bash"},

		{name: "contains", predicate: Predicate{Contains: sp("-c")}, match: "python -c pass", noMatch: "python script.py"},
		{name: "contains nocase", predicate: Predicate{Contains: sp("PowerShell"), NoCase: true}, match: "C:/x/powershell.exe", noMatch: "cmd.exe"},
		{name: "contains nocase non-ASCII", predicate: Predicate{Contains: sp("ÉCOLE"), NoCase: true}, match: "une école ici", noMatch: "ecole"},

		{name: "prefix", predicate: Predicate{Prefix: sp("/tmp/")}, match: "/tmp/x", noMatch: "/var/tmp/x"},
		{name: "prefix nocase", predicate: Predicate{Prefix: sp("c:/users"), NoCase: true}, match: "C:/Users/bob", noMatch: "D:/Users"},
		{name: "prefix longer than value", predicate: Predicate{Prefix: sp("/tmp/long"), NoCase: true}, match: "/TMP/LONG", noMatch: "/tmp"},

		{name: "suffix", predicate: Predicate{Suffix: sp(".sh")}, match: "run.sh", noMatch: "run.sh.bak"},
		{name: "suffix nocase", predicate: Predicate{Suffix: sp(".EXE"), NoCase: true}, match: "a.exe", noMatch: "a.ex"},

		{name: "glob star stays within a segment", predicate: Predicate{Glob: sp("/tmp/*")}, match: "/tmp/a", noMatch: "/tmp/a/b"},
		{name: "glob double star crosses segments", predicate: Predicate{Glob: sp("/tmp/**")}, match: "/tmp/a/b/c", noMatch: "/var/a"},
		{name: "glob double star matches zero segments", predicate: Predicate{Glob: sp("/home/**/.ssh/id_*")}, match: "/home/.ssh/id_rsa", noMatch: "/home/bob/.ssh/known_hosts"},
		{name: "glob double star in the middle", predicate: Predicate{Glob: sp("/home/**/.ssh/id_*")}, match: "/home/a/b/.ssh/id_ed25519", noMatch: "/root/.ssh/id_rsa"},
		{name: "glob question mark", predicate: Predicate{Glob: sp("python?")}, match: "python3", noMatch: "python"},
		{name: "glob class", predicate: Predicate{Glob: sp("python[23]")}, match: "python2", noMatch: "python4"},
		{name: "glob negated class", predicate: Predicate{Glob: sp("file[!0-9]")}, match: "filex", noMatch: "file7"},
		{name: "glob treats regex characters literally", predicate: Predicate{Glob: sp("a.b+c(1)")}, match: "a.b+c(1)", noMatch: "aXb+c(1)"},
		{name: "glob escape", predicate: Predicate{Glob: sp(`literal\*`)}, match: "literal*", noMatch: "literalx"},
		{name: "glob nocase", predicate: Predicate{Glob: sp("*.PS1"), NoCase: true}, match: "run.ps1", noMatch: "run.ps"},
		{name: "glob on a domain", predicate: Predicate{Glob: sp("**.example.com")}, match: "a.b.example.com", noMatch: "example.org"},

		{name: "regex", predicate: Predicate{Regex: sp(`^python[0-9.]*$`)}, match: "python3.12", noMatch: "pythonw"},
		{name: "regex is unanchored unless written so", predicate: Predicate{Regex: sp(`\.(ru|cn)$`)}, match: "evil.ru", noMatch: "ru.example.com"},
		{name: "regex nocase", predicate: Predicate{Regex: sp(`^cmd\.exe$`), NoCase: true}, match: "CMD.EXE", noMatch: "cmd.exe.bak"},
		{name: "regex that matches empty still excludes missing", predicate: Predicate{Regex: sp(`^.*$`)}, match: "anything", noMatch: ""},

		{name: "cidr IPv4", kind: kindAddress, predicate: Predicate{CIDR: []string{"10.0.0.0/8"}}, match: "10.20.30.40", noMatch: "11.0.0.1"},
		{name: "cidr list", kind: kindAddress, predicate: Predicate{CIDR: []string{"10.0.0.0/8", "127.0.0.0/8"}}, match: "127.0.0.1", noMatch: "8.8.8.8"},
		{name: "cidr IPv6", kind: kindAddress, predicate: Predicate{CIDR: []string{"fd00::/8"}}, match: "fd12:3456::1", noMatch: "2001:db8::1"},
		{name: "cidr IPv6 loopback", kind: kindAddress, predicate: Predicate{CIDR: []string{"::1/128"}}, match: "::1", noMatch: "::2"},
		{name: "cidr mixed families", kind: kindAddress, predicate: Predicate{CIDR: []string{"192.168.0.0/16", "fe80::/10"}}, match: "fe80::1", noMatch: "172.16.0.1"},
		{name: "cidr IPv4-mapped IPv6 address", kind: kindAddress, predicate: Predicate{CIDR: []string{"10.0.0.0/8"}}, match: "::ffff:10.1.2.3", noMatch: "::ffff:11.1.2.3"},
		{name: "cidr bare address", kind: kindAddress, predicate: Predicate{CIDR: []string{"1.2.3.4"}}, match: "1.2.3.4", noMatch: "1.2.3.5"},
		{name: "cidr on a value that is not an address", kind: kindAddress, predicate: Predicate{CIDR: []string{"0.0.0.0/0"}}, match: "9.9.9.9", noMatch: "localhost"},
		{name: "address fields take string operators too", kind: kindAddress, predicate: Predicate{Prefix: sp("192.168.")}, match: "192.168.1.1", noMatch: "10.0.0.1"},

		// not: true for a missing value whenever the wrapped operator is false for it.
		{name: "not eq", predicate: Predicate{Not: &Predicate{Eq: sp("root")}}, match: "alice", noMatch: "root", missing: true},
		{name: "not in", predicate: Predicate{Not: &Predicate{In: []string{"root", "admin"}}}, match: "alice", noMatch: "admin", missing: true},
		{name: "not prefix", predicate: Predicate{Not: &Predicate{Prefix: sp("/usr/")}}, match: "/tmp/x", noMatch: "/usr/bin/x", missing: true},
		{name: "not cidr", kind: kindAddress, predicate: Predicate{Not: &Predicate{CIDR: []string{"10.0.0.0/8", "::1/128"}}}, match: "8.8.8.8", noMatch: "::1", missing: true},
		{name: "not eq empty means present", predicate: Predicate{Not: &Predicate{Eq: sp("")}}, match: "x", noMatch: "", missing: false},
		{name: "double not", predicate: Predicate{Not: &Predicate{Not: &Predicate{Eq: sp("a")}}}, match: "a", noMatch: "b"},
		{name: "not with nocase inside", predicate: Predicate{Not: &Predicate{Eq: sp("ROOT"), NoCase: true}}, match: "bob", noMatch: "root", missing: true},

		// Several operators in one object are ANDed.
		{name: "prefix and suffix", predicate: Predicate{Prefix: sp("/tmp/"), Suffix: sp(".sh")}, match: "/tmp/a.sh", noMatch: "/tmp/a.py"},
		{name: "regex and not contains", predicate: Predicate{Regex: sp("^py"), Not: &Predicate{Contains: sp("3")}}, match: "python", noMatch: "python3"},
	}

	for _, c := range cases {
		test, err := compileStringPredicate(c.predicate, c.kind)
		if err != nil {
			t.Errorf("%s: compile: %v", c.name, err)
			continue
		}

		// A case whose "match" value is itself empty is about the missing
		// value and is covered by the missing check below.
		if c.match != "" && !test(c.match, true) {
			t.Errorf("%s: %q should match", c.name, c.match)
		}
		if c.noMatch != "" && test(c.noMatch, true) {
			t.Errorf("%s: %q should not match", c.name, c.noMatch)
		}
		if got := test("", false); got != c.missing {
			t.Errorf("%s: missing value matched = %v, want %v", c.name, got, c.missing)
		}
	}
}

func TestNumericOperators(t *testing.T) {
	cases := []struct {
		name      string
		predicate Predicate
		match     []int64
		noMatch   []int64
		missing   bool
	}{
		{name: "eq", predicate: Predicate{Eq: sp("443")}, match: []int64{443}, noMatch: []int64{80, 4430}},
		{name: "eq zero is a real value", predicate: Predicate{Eq: sp("0")}, match: []int64{0}, noMatch: []int64{1}},
		{name: "in", predicate: Predicate{In: []string{"80", "443", "53"}}, match: []int64{53, 80}, noMatch: []int64{8080}},
		{name: "gt", predicate: Predicate{Gt: sp("1024")}, match: []int64{1025, 65535}, noMatch: []int64{1024, 80}},
		{name: "gte", predicate: Predicate{Gte: sp("1024")}, match: []int64{1024, 1025}, noMatch: []int64{1023}},
		{name: "lt", predicate: Predicate{Lt: sp("1024")}, match: []int64{1023, 0}, noMatch: []int64{1024}},
		{name: "lte", predicate: Predicate{Lte: sp("1024")}, match: []int64{1024, 22}, noMatch: []int64{1025}},
		{name: "range", predicate: Predicate{Gte: sp("8000"), Lte: sp("8999")}, match: []int64{8000, 8443, 8999}, noMatch: []int64{7999, 9000}},
		{name: "not in", predicate: Predicate{Not: &Predicate{In: []string{"80", "443", "53"}}}, match: []int64{4444}, noMatch: []int64{443}, missing: true},
		{name: "not range", predicate: Predicate{Not: &Predicate{Gte: sp("1"), Lte: sp("1023")}}, match: []int64{0, 1024}, noMatch: []int64{22}, missing: true},
		{name: "values may have surrounding space", predicate: Predicate{Eq: sp(" 22 ")}, match: []int64{22}, noMatch: []int64{23}},
	}

	for _, c := range cases {
		test, err := compileNumberPredicate(c.predicate)
		if err != nil {
			t.Errorf("%s: compile: %v", c.name, err)
			continue
		}
		for _, value := range c.match {
			if !test(value, true) {
				t.Errorf("%s: %d should match", c.name, value)
			}
		}
		for _, value := range c.noMatch {
			if test(value, true) {
				t.Errorf("%s: %d should not match", c.name, value)
			}
		}
		if got := test(0, false); got != c.missing {
			t.Errorf("%s: missing value matched = %v, want %v", c.name, got, c.missing)
		}
	}
}

func TestPredicateCompileErrors(t *testing.T) {
	stringErrors := map[string]struct {
		predicate Predicate
		kind      fieldKind
		want      string
	}{
		"cidr on a string field":     {Predicate{CIDR: []string{"10.0.0.0/8"}}, kindString, `operator "cidr" is not valid for a string field`},
		"gt on a string field":       {Predicate{Gt: sp("5")}, kindString, `operator "gt" is not valid for a string field`},
		"lte on an address field":    {Predicate{Lte: sp("5")}, kindAddress, `operator "lte" is not valid for a address field`},
		"bad regex":                  {Predicate{Regex: sp("([a-z")}, kindString, `bad regex "([a-z"`},
		"bad glob":                   {Predicate{Glob: sp("file[abc")}, kindString, `bad glob "file[abc"`},
		"bad glob trailing escape":   {Predicate{Glob: sp(`dir\`)}, kindString, "trailing backslash"},
		"bad cidr":                   {Predicate{CIDR: []string{"10.0.0.0/33"}}, kindAddress, `bad cidr "10.0.0.0/33"`},
		"cidr that is not a network": {Predicate{CIDR: []string{"localnet"}}, kindAddress, `bad cidr "localnet"`},
		"empty cidr list":            {Predicate{CIDR: []string{}}, kindAddress, `"cidr" needs at least one network`},
		"empty in list":              {Predicate{In: []string{}}, kindString, `"in" needs at least one value`},
		"no operator":                {Predicate{}, kindString, "no operator given"},
		"nocase alone":               {Predicate{NoCase: true}, kindString, "no operator given"},
		"error inside not":           {Predicate{Not: &Predicate{Regex: sp("(")}}, kindString, "not: bad regex"},
	}
	for name, c := range stringErrors {
		_, err := compileStringPredicate(c.predicate, c.kind)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %v, want it to mention %q", name, err, c.want)
		}
	}

	numberErrors := map[string]struct {
		predicate Predicate
		want      string
	}{
		"contains on a number": {Predicate{Contains: sp("4")}, `operator "contains" is not valid for a numeric field`},
		"regex on a number":    {Predicate{Regex: sp("4")}, `operator "regex" is not valid for a numeric field`},
		"glob on a number":     {Predicate{Glob: sp("4*")}, `operator "glob" is not valid for a numeric field`},
		"cidr on a number":     {Predicate{CIDR: []string{"1.1.1.1"}}, `operator "cidr" is not valid for a numeric field`},
		"nocase on a number":   {Predicate{Eq: sp("1"), NoCase: true}, `operator "nocase" is not valid for a numeric field`},
		"text for eq":          {Predicate{Eq: sp("https")}, `"eq" needs an integer, got "https"`},
		"text in list":         {Predicate{In: []string{"80", "http"}}, `"in" needs an integer, got "http"`},
		"fraction for gt":      {Predicate{Gt: sp("1.5")}, `"gt" needs an integer`},
		"empty in list":        {Predicate{In: []string{}}, `"in" needs at least one value`},
		"no operator":          {Predicate{}, "no operator given"},
	}
	for name, c := range numberErrors {
		_, err := compileNumberPredicate(c.predicate)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %v, want it to mention %q", name, err, c.want)
		}
	}
}

func fieldIs(name string, p Predicate) FieldPredicate {
	return FieldPredicate{Field: name, Predicate: p}
}

func TestProcessMatchBlock(t *testing.T) {
	python := core.Process{Name: "python3", Executable: "/tmp/python3", CommandLine: "python3 -c pass", User: "www-data"}
	system := core.Process{Name: "python3", Executable: "/usr/bin/python3", CommandLine: "python3 app.py", User: "root"}
	nameless := core.Process{PID: 7}

	cases := []struct {
		name  string
		block MatchBlock
		want  map[*core.Process]bool
	}{
		{
			name: "all fields are ANDed",
			block: MatchBlock{Fields: []FieldPredicate{
				fieldIs("name", Predicate{Regex: sp(`^python[0-9.]*$`)}),
				fieldIs("user", Predicate{Not: &Predicate{Eq: sp("root")}}),
				fieldIs("cmdline", Predicate{Contains: sp("-c")}),
			}},
			want: map[*core.Process]bool{&python: true, &system: false, &nameless: false},
		},
		{
			name: "any_of needs one alternative",
			block: MatchBlock{AnyOf: []MatchBlock{
				{Fields: []FieldPredicate{fieldIs("exe", Predicate{Prefix: sp("/tmp/")})}},
				{Fields: []FieldPredicate{fieldIs("exe", Predicate{Prefix: sp("/dev/shm/")})}},
			}},
			want: map[*core.Process]bool{&python: true, &system: false, &nameless: false},
		},
		{
			name: "fields and any_of together",
			block: MatchBlock{
				Fields: []FieldPredicate{fieldIs("name", Predicate{Prefix: sp("python")})},
				AnyOf: []MatchBlock{
					{Fields: []FieldPredicate{fieldIs("user", Predicate{Eq: sp("root")})}},
					{Fields: []FieldPredicate{fieldIs("exe", Predicate{Prefix: sp("/tmp/")})}},
				},
			},
			want: map[*core.Process]bool{&python: true, &system: true, &nameless: false},
		},
		{
			name: "nested any_of",
			block: MatchBlock{AnyOf: []MatchBlock{
				{Fields: []FieldPredicate{fieldIs("user", Predicate{Eq: sp("nobody")})}},
				{
					Fields: []FieldPredicate{fieldIs("user", Predicate{Eq: sp("www-data")})},
					AnyOf: []MatchBlock{
						{Fields: []FieldPredicate{fieldIs("cmdline", Predicate{Contains: sp("--never")})}},
						{Fields: []FieldPredicate{fieldIs("cmdline", Predicate{Suffix: sp("pass")})}},
					},
				},
			}},
			want: map[*core.Process]bool{&python: true, &system: false, &nameless: false},
		},
		{
			name: "missing fields match only eq empty and not",
			block: MatchBlock{Fields: []FieldPredicate{
				fieldIs("name", Predicate{Eq: sp("")}),
				fieldIs("exe", Predicate{Not: &Predicate{Prefix: sp("/usr/")}}),
			}},
			want: map[*core.Process]bool{&python: false, &system: false, &nameless: true},
		},
		{
			// Decided where the field is read, not by the operator: an
			// expression that would match the empty string still does not
			// match a missing value.
			name: "operators that accept empty text still reject a missing field",
			block: MatchBlock{AnyOf: []MatchBlock{
				{Fields: []FieldPredicate{fieldIs("name", Predicate{Regex: sp(`^.*$`)})}},
				{Fields: []FieldPredicate{fieldIs("name", Predicate{Prefix: sp("")})}},
				{Fields: []FieldPredicate{fieldIs("name", Predicate{Glob: sp("**")})}},
				{Fields: []FieldPredicate{fieldIs("name", Predicate{Contains: sp("")})}},
			}},
			want: map[*core.Process]bool{&python: true, &nameless: false},
		},
		{
			name:  "an empty block matches everything",
			block: MatchBlock{},
			want:  map[*core.Process]bool{&python: true, &system: true, &nameless: true},
		},
	}

	for _, c := range cases {
		matches, err := compileProcessMatch(&c.block, "match")
		if err != nil {
			t.Errorf("%s: compile: %v", c.name, err)
			continue
		}
		for process, want := range c.want {
			if got := matches(process); got != want {
				t.Errorf("%s: %s (%s) matched = %v, want %v", c.name, process.Name, process.User, got, want)
			}
		}
	}
}

func TestEventWhereFields(t *testing.T) {
	connect := core.Event{Type: core.EventNetworkConnect, Network: &core.NetworkConnection{
		RemoteAddress: "203.0.113.9", RemotePort: 4444, LocalPort: 51000, Protocol: "tcp", State: "ESTABLISHED",
	}}
	bare := core.Event{Type: core.EventNetworkConnect} // nothing attached
	query := core.Event{Type: core.EventDNSQuery, DNS: &core.DNSQuery{Domain: "c2.evil.ru", Type: "A", Resolver: "8.8.8.8"}}
	rename := core.Event{Type: core.EventFileRename, File: &core.FileEvent{Path: "/etc/cron.d/x", OldPath: "/tmp/x"}}

	cases := []struct {
		name  string
		event *core.Event
		field string
		p     Predicate
		want  bool
	}{
		{"remote_addr cidr", &connect, "remote_addr", Predicate{CIDR: []string{"203.0.113.0/24"}}, true},
		{"remote_addr not private", &connect, "remote_addr", Predicate{Not: &Predicate{CIDR: []string{"10.0.0.0/8", "127.0.0.0/8", "::1/128"}}}, true},
		{"remote_port not in", &connect, "remote_port", Predicate{Not: &Predicate{In: []string{"80", "443", "53"}}}, true},
		{"remote_port eq mismatch", &connect, "remote_port", Predicate{Eq: sp("443")}, false},
		{"local_port gte", &connect, "local_port", Predicate{Gte: sp("49152")}, true},
		{"protocol", &connect, "protocol", Predicate{Eq: sp("TCP"), NoCase: true}, true},
		{"state", &connect, "state", Predicate{In: []string{"LISTEN"}}, false},

		{"no network data: positive operator", &bare, "remote_port", Predicate{Gt: sp("0")}, false},
		{"no network data: eq zero is not missing", &bare, "remote_port", Predicate{Eq: sp("0")}, false},
		{"no network data: not", &bare, "remote_port", Predicate{Not: &Predicate{In: []string{"80"}}}, true},
		{"no network data: address eq empty", &bare, "remote_addr", Predicate{Eq: sp("")}, true},

		{"domain suffix", &query, "domain", Predicate{Suffix: sp(".ru")}, true},
		{"domain regex over a TLD list", &query, "domain", Predicate{Regex: sp(`\.(ru|top|xyz)$`)}, true},
		{"query_type", &query, "query_type", Predicate{In: []string{"TXT", "NULL"}}, false},
		{"resolver cidr", &query, "resolver", Predicate{Not: &Predicate{CIDR: []string{"192.168.0.0/16"}}}, true},

		{"path glob", &rename, "path", Predicate{Glob: sp("/etc/cron*/**")}, true},
		{"old_path prefix", &rename, "old_path", Predicate{Prefix: sp("/tmp/")}, true},
	}

	for _, c := range cases {
		block := MatchBlock{Fields: []FieldPredicate{fieldIs(c.field, c.p)}}
		where, err := compileEventWhere(&block, c.event.Type, "where")
		if err != nil {
			t.Errorf("%s: compile: %v", c.name, err)
			continue
		}
		if got := where(c.event); got != c.want {
			t.Errorf("%s: matched = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMatchBlockCompileErrors(t *testing.T) {
	block := func(fields ...FieldPredicate) *MatchBlock { return &MatchBlock{Fields: fields} }

	processErrors := map[string]struct {
		block *MatchBlock
		want  []string
	}{
		"unknown field":         {block(fieldIs("colour", Predicate{Eq: sp("x")})), []string{"match.colour", "unknown field", "cmdline, exe, name, user"}},
		"cidr on name":          {block(fieldIs("name", Predicate{CIDR: []string{"10.0.0.0/8"}})), []string{"match.name", `"cidr" is not valid for a string field`}},
		"bad regex":             {block(fieldIs("cmdline", Predicate{Regex: sp("(")})), []string{"match.cmdline", "bad regex"}},
		"empty any_of":          {&MatchBlock{AnyOf: []MatchBlock{}}, []string{"match.any_of", "at least one alternative"}},
		"error inside any_of":   {&MatchBlock{AnyOf: []MatchBlock{{}, *block(fieldIs("exe", Predicate{Gt: sp("1")}))}}, []string{"match.any_of[1].exe", `"gt" is not valid`}},
		"event field on a role": {block(fieldIs("remote_port", Predicate{Eq: sp("22")})), []string{"match.remote_port", "unknown field"}},
	}
	for name, c := range processErrors {
		_, err := compileProcessMatch(c.block, "match")
		for _, want := range c.want {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error = %v, want it to mention %q", name, err, want)
			}
		}
	}

	eventErrors := map[string]struct {
		eventType core.EventType
		block     *MatchBlock
		want      []string
	}{
		"dns field on a network event":  {core.EventNetworkConnect, block(fieldIs("domain", Predicate{Eq: sp("x")})), []string{"where.domain", "unknown field", "remote_addr"}},
		"network field on a dns event":  {core.EventDNSQuery, block(fieldIs("remote_port", Predicate{Eq: sp("53")})), []string{"where.remote_port", "unknown field", "domain"}},
		"gt on path":                    {core.EventFileCreate, block(fieldIs("path", Predicate{Gt: sp("1")})), []string{"where.path", `"gt" is not valid for a string field`}},
		"contains on a port":            {core.EventNetworkConnect, block(fieldIs("remote_port", Predicate{Contains: sp("4")})), []string{"where.remote_port", `"contains" is not valid for a numeric field`}},
		"cidr on protocol":              {core.EventNetworkConnect, block(fieldIs("protocol", Predicate{CIDR: []string{"::/0"}})), []string{"where.protocol", `"cidr" is not valid`}},
		"event type with no fields":     {core.EventPersistenceChange, block(fieldIs("path", Predicate{Eq: sp("x")})), []string{"where", "PERSISTENCE_CHANGE events have no fields"}},
		"file field on a process event": {core.EventProcessStart, block(fieldIs("path", Predicate{Eq: sp("x")})), []string{"where.path", "unknown field", "cmdline, exe, name, user"}},
	}
	for name, c := range eventErrors {
		_, err := compileEventWhere(c.block, c.eventType, "where")
		for _, want := range c.want {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error = %v, want it to mention %q", name, err, want)
			}
		}
	}
}

// Compiled predicates must not allocate when they run: they are evaluated
// for every candidate process and event.
func TestCompiledPredicatesDoNotAllocate(t *testing.T) {
	processMatch, err := compileProcessMatch(&MatchBlock{
		Fields: []FieldPredicate{
			fieldIs("name", Predicate{Regex: sp(`^python[0-9.]*$`)}),
			fieldIs("user", Predicate{Not: &Predicate{Eq: sp("root")}}),
			fieldIs("cmdline", Predicate{Contains: sp("-C"), NoCase: true}),
		},
		AnyOf: []MatchBlock{
			{Fields: []FieldPredicate{fieldIs("exe", Predicate{Glob: sp("/tmp/**")})}},
			{Fields: []FieldPredicate{fieldIs("exe", Predicate{Prefix: sp("/dev/shm/")})}},
		},
	}, "match")
	if err != nil {
		t.Fatal(err)
	}

	where, err := compileEventWhere(&MatchBlock{Fields: []FieldPredicate{
		fieldIs("remote_port", Predicate{Not: &Predicate{In: []string{"80", "443", "53"}}}),
		fieldIs("remote_addr", Predicate{Not: &Predicate{CIDR: []string{"10.0.0.0/8", "127.0.0.0/8", "::1/128"}}}),
	}}, core.EventNetworkConnect, "where")
	if err != nil {
		t.Fatal(err)
	}

	process := &core.Process{Name: "python3.12", User: "www-data", CommandLine: "python3 -c pass", Executable: "/tmp/a/b/python3"}
	event := &core.Event{Type: core.EventNetworkConnect, Network: &core.NetworkConnection{RemoteAddress: "2001:db8::7", RemotePort: 4444}}

	if !processMatch(process) || !where(event) {
		t.Fatal("test inputs should match")
	}

	if allocs := testing.AllocsPerRun(200, func() { processMatch(process) }); allocs != 0 {
		t.Errorf("process match allocates %v times per run", allocs)
	}
	if allocs := testing.AllocsPerRun(200, func() { where(event) }); allocs != 0 {
		t.Errorf("event filter allocates %v times per run", allocs)
	}
}
