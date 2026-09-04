package process

type Registry struct {
	rules []Rule
}

func NewRegistry() *Registry {
	return &Registry{
		rules: make([]Rule, 0),
	}
}

func (r *Registry) Register(rule Rule) {
	r.rules = append(r.rules, rule)
}

func (r *Registry) Rules() []Rule {
	return r.rules
}
