package correlation

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Predicate is one operator object as written in a pattern, for example
// {prefix: /tmp/, nocase: true}. Every operator that is set must hold.
//
// Values are kept as the scalar text that was written; they are interpreted
// when the pattern is compiled, according to the kind of field they apply
// to. A nil pointer or slice means the operator was not written.
type Predicate struct {
	Eq       *string
	In       []string
	Contains *string
	Prefix   *string
	Suffix   *string
	Glob     *string
	Regex    *string
	CIDR     []string
	Gt       *string
	Gte      *string
	Lt       *string
	Lte      *string
	// Not inverts the operator object it wraps.
	Not *Predicate
	// NoCase makes the string operators of this object case-insensitive.
	NoCase bool
	// Shorthand records that the predicate was written as a bare scalar
	// (meaning Eq) or a bare list (meaning In), so it is saved the same way.
	Shorthand bool
}

// FieldPredicate applies a predicate to one named field.
type FieldPredicate struct {
	Field     string
	Predicate Predicate
}

// MatchBlock is a set of field predicates that must all hold, optionally
// together with alternatives of which at least one must hold. It is used
// both to match a process (a role's match block, exclusions) and to filter
// events (an event's where block).
type MatchBlock struct {
	Fields []FieldPredicate
	// AnyOf holds alternative blocks; at least one must match. Blocks may
	// nest.
	AnyOf []MatchBlock
}

// IsEmpty reports whether the block places no requirement at all. A block
// whose any_of was written but left empty is not empty: it is a mistake, and
// compiling it says so.
func (b *MatchBlock) IsEmpty() bool {
	return b == nil || (len(b.Fields) == 0 && b.AnyOf == nil)
}

// fieldKind says which operators a field accepts.
type fieldKind int

const (
	kindString  fieldKind = iota // text
	kindAddress                  // text holding an IP address: string operators plus cidr
	kindNumber                   // integer
)

func (k fieldKind) String() string {
	switch k {
	case kindAddress:
		return "address"
	case kindNumber:
		return "numeric"
	default:
		return "string"
	}
}

// A value that is missing (an empty string, or a field of a part of the event
// that is absent) satisfies only eq: "" among the positive operators. Every
// other operator is false for it, so wrapping one in not: makes it true.

// stringTest decides a string or address field. present is false when the
// value is missing.
type stringTest func(value string, present bool) bool

// numberTest decides a numeric field.
type numberTest func(value int64, present bool) bool

// compileStringPredicate turns a predicate into a test for a string or
// address field.
func compileStringPredicate(p Predicate, kind fieldKind) (stringTest, error) {
	var tests []stringTest

	for _, numeric := range []struct {
		name  string
		value *string
	}{{"gt", p.Gt}, {"gte", p.Gte}, {"lt", p.Lt}, {"lte", p.Lte}} {
		if numeric.value != nil {
			return nil, wrongKind(numeric.name, kind)
		}
	}

	if p.Eq != nil {
		want := *p.Eq
		equal := equalFunc(p.NoCase)
		tests = append(tests, func(value string, present bool) bool {
			if !present {
				return want == ""
			}
			return equal(value, want)
		})
	}

	if p.In != nil {
		if len(p.In) == 0 {
			return nil, fmt.Errorf(`"in" needs at least one value`)
		}
		options := append([]string(nil), p.In...)
		equal := equalFunc(p.NoCase)
		tests = append(tests, func(value string, present bool) bool {
			if !present {
				return false
			}
			for _, option := range options {
				if equal(value, option) {
					return true
				}
			}
			return false
		})
	}

	if p.Contains != nil {
		tests = append(tests, presentOnly(containsFunc(*p.Contains, p.NoCase)))
	}
	if p.Prefix != nil {
		tests = append(tests, presentOnly(prefixFunc(*p.Prefix, p.NoCase)))
	}
	if p.Suffix != nil {
		tests = append(tests, presentOnly(suffixFunc(*p.Suffix, p.NoCase)))
	}

	if p.Glob != nil {
		expression, err := globToRegexp(*p.Glob, p.NoCase)
		if err != nil {
			return nil, fmt.Errorf("bad glob %q: %w", *p.Glob, err)
		}
		tests = append(tests, presentOnly(expression.MatchString))
	}

	if p.Regex != nil {
		source := *p.Regex
		if p.NoCase {
			source = "(?i)" + source
		}
		expression, err := regexp.Compile(source)
		if err != nil {
			return nil, fmt.Errorf("bad regex %q: %w", *p.Regex, err)
		}
		tests = append(tests, presentOnly(expression.MatchString))
	}

	if p.CIDR != nil {
		if kind != kindAddress {
			return nil, wrongKind("cidr", kind)
		}
		test, err := cidrTest(p.CIDR)
		if err != nil {
			return nil, err
		}
		tests = append(tests, presentOnly(test))
	}

	if p.Not != nil {
		inner, err := compileStringPredicate(*p.Not, kind)
		if err != nil {
			return nil, fmt.Errorf("not: %w", err)
		}
		tests = append(tests, func(value string, present bool) bool {
			return !inner(value, present)
		})
	}

	switch len(tests) {
	case 0:
		return nil, fmt.Errorf("no operator given")
	case 1:
		return tests[0], nil
	}

	return func(value string, present bool) bool {
		for _, test := range tests {
			if !test(value, present) {
				return false
			}
		}
		return true
	}, nil
}

// compileNumberPredicate turns a predicate into a test for a numeric field.
func compileNumberPredicate(p Predicate) (numberTest, error) {
	var tests []numberTest

	for _, textual := range []struct {
		name string
		set  bool
	}{
		{"contains", p.Contains != nil}, {"prefix", p.Prefix != nil}, {"suffix", p.Suffix != nil},
		{"glob", p.Glob != nil}, {"regex", p.Regex != nil}, {"cidr", p.CIDR != nil}, {"nocase", p.NoCase},
	} {
		if textual.set {
			return nil, wrongKind(textual.name, kindNumber)
		}
	}

	if p.Eq != nil {
		want, err := parseNumber("eq", *p.Eq)
		if err != nil {
			return nil, err
		}
		tests = append(tests, func(value int64, present bool) bool {
			return present && value == want
		})
	}

	if p.In != nil {
		if len(p.In) == 0 {
			return nil, fmt.Errorf(`"in" needs at least one value`)
		}
		options := make([]int64, len(p.In))
		for i, text := range p.In {
			option, err := parseNumber("in", text)
			if err != nil {
				return nil, err
			}
			options[i] = option
		}
		tests = append(tests, func(value int64, present bool) bool {
			if !present {
				return false
			}
			for _, option := range options {
				if value == option {
					return true
				}
			}
			return false
		})
	}

	for _, bound := range []struct {
		name    string
		value   *string
		compare func(value, bound int64) bool
	}{
		{"gt", p.Gt, func(v, b int64) bool { return v > b }},
		{"gte", p.Gte, func(v, b int64) bool { return v >= b }},
		{"lt", p.Lt, func(v, b int64) bool { return v < b }},
		{"lte", p.Lte, func(v, b int64) bool { return v <= b }},
	} {
		if bound.value == nil {
			continue
		}
		limit, err := parseNumber(bound.name, *bound.value)
		if err != nil {
			return nil, err
		}
		compare := bound.compare
		tests = append(tests, func(value int64, present bool) bool {
			return present && compare(value, limit)
		})
	}

	if p.Not != nil {
		inner, err := compileNumberPredicate(*p.Not)
		if err != nil {
			return nil, fmt.Errorf("not: %w", err)
		}
		tests = append(tests, func(value int64, present bool) bool {
			return !inner(value, present)
		})
	}

	switch len(tests) {
	case 0:
		return nil, fmt.Errorf("no operator given")
	case 1:
		return tests[0], nil
	}

	return func(value int64, present bool) bool {
		for _, test := range tests {
			if !test(value, present) {
				return false
			}
		}
		return true
	}, nil
}

func wrongKind(operator string, kind fieldKind) error {
	return fmt.Errorf("operator %q is not valid for a %s field", operator, kind)
}

func parseNumber(operator, text string) (int64, error) {
	number, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q needs an integer, got %q", operator, text)
	}
	return number, nil
}

// presentOnly makes a plain string test false for a missing value.
func presentOnly(test func(string) bool) stringTest {
	return func(value string, present bool) bool {
		return present && test(value)
	}
}

func equalFunc(nocase bool) func(a, b string) bool {
	if nocase {
		return strings.EqualFold
	}
	return func(a, b string) bool { return a == b }
}

func prefixFunc(prefix string, nocase bool) func(string) bool {
	if !nocase {
		return func(value string) bool { return strings.HasPrefix(value, prefix) }
	}
	return func(value string) bool {
		return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
	}
}

func suffixFunc(suffix string, nocase bool) func(string) bool {
	if !nocase {
		return func(value string) bool { return strings.HasSuffix(value, suffix) }
	}
	return func(value string) bool {
		return len(value) >= len(suffix) && strings.EqualFold(value[len(value)-len(suffix):], suffix)
	}
}

func containsFunc(needle string, nocase bool) func(string) bool {
	if !nocase {
		return func(value string) bool { return strings.Contains(value, needle) }
	}

	// Case-insensitive search without building a lowered copy of the value
	// for every event. Patterns are almost always ASCII; anything else goes
	// through a regular expression, which folds case properly.
	if !isASCII(needle) {
		expression := regexp.MustCompile("(?i)" + regexp.QuoteMeta(needle))
		return expression.MatchString
	}

	return func(value string) bool {
		for i := 0; i+len(needle) <= len(value); i++ {
			if strings.EqualFold(value[i:i+len(needle)], needle) {
				return true
			}
		}
		return false
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// cidrTest builds a test that an address lies in any of the given networks.
// IPv4 and IPv6 may be mixed; an IPv4-mapped IPv6 address is treated as the
// IPv4 address it carries. A value that is not an address is not in any
// network.
func cidrTest(networks []string) (func(string) bool, error) {
	if len(networks) == 0 {
		return nil, fmt.Errorf(`"cidr" needs at least one network`)
	}

	prefixes := make([]netip.Prefix, len(networks))
	for i, text := range networks {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(text))
		if err != nil {
			// A bare address means that one host.
			address, addressErr := netip.ParseAddr(strings.TrimSpace(text))
			if addressErr != nil {
				return nil, fmt.Errorf("bad cidr %q: %w", text, err)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		prefixes[i] = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked()
	}

	return func(value string) bool {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return false
		}
		address = address.Unmap()

		for _, prefix := range prefixes {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}, nil
}

// globToRegexp compiles a glob to an anchored regular expression.
//
//   - any run of characters except "/"
//     **      any run of characters, "/" included; "**/" also matches nothing,
//     so "/a/**/b" matches "/a/b"
//     ?       one character except "/"
//     [abc]   one of the listed characters; ranges and a leading "!" or "^" work
//     \x      the character x, literally
func globToRegexp(glob string, nocase bool) (*regexp.Regexp, error) {
	var b strings.Builder

	if nocase {
		b.WriteString("(?i)")
	}
	b.WriteString("^")

	for i := 0; i < len(glob); {
		switch c := glob[i]; c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i += 2
				if i < len(glob) && glob[i] == '/' {
					b.WriteString("(?:.*/)?")
					i++
				} else {
					b.WriteString(".*")
				}
				continue
			}
			b.WriteString("[^/]*")
			i++

		case '?':
			b.WriteString("[^/]")
			i++

		case '[':
			end := strings.IndexByte(glob[i+1:], ']')
			// "[]" and "[!]" do not close a class: the first "]" is a member.
			if end == 0 || (end == 1 && (glob[i+1] == '!' || glob[i+1] == '^')) {
				next := strings.IndexByte(glob[i+2+end:], ']')
				if next < 0 {
					end = -1
				} else {
					end += next + 1
				}
			}
			if end < 0 {
				return nil, fmt.Errorf("unclosed character class")
			}

			class := glob[i+1 : i+1+end]
			b.WriteByte('[')
			if class[0] == '!' || class[0] == '^' {
				b.WriteByte('^')
				class = class[1:]
			}
			b.WriteString(strings.ReplaceAll(class, `\`, `\\`))
			b.WriteByte(']')
			i += end + 2

		case '\\':
			if i+1 >= len(glob) {
				return nil, fmt.Errorf("trailing backslash")
			}
			b.WriteString(regexp.QuoteMeta(glob[i+1 : i+2]))
			i += 2

		default:
			_, size := utf8.DecodeRuneInString(glob[i:])
			b.WriteString(regexp.QuoteMeta(glob[i : i+size]))
			i += size
		}
	}

	b.WriteString("$")

	return regexp.Compile(b.String())
}

// fieldNames lists the keys of a field table, for error messages.
func fieldNames[T any](fields map[string]T) string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)

	return strings.Join(names, ", ")
}
