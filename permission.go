package principal

import "gopkg.in/fatih/set.v0"

type Permission interface {
	Tag() string
	Needs(...interface{}) *set.Set
	Excludes(...interface{}) *set.Set
	Allows(Identity) bool
	Requires(Identity) bool
}

type permission struct {
	tag      string
	needs    *set.Set
	excludes *set.Set
}

func NewPermission(tag string, needs ...interface{}) Permission {
	return &permission{
		tag:   tag,
		needs: set.New(needs...),
	}
}

func (p *permission) Tag() string {
	return p.tag
}

func (p *permission) Needs(needs ...interface{}) *set.Set {
	p.needs.Add(needs...)
	return p.needs
}

func (p *permission) Excludes(excludes ...interface{}) *set.Set {
	p.excludes.Add(excludes...)
	return p.excludes
}

// Allows checks the intersection of permission needs and identity provides.
// Returns true if the intersection is not empty.
func (p *permission) Allows(i Identity) bool {
	return !set.Intersection(p.needs, i.Provides()).IsEmpty()
}

// Requires checks that given identity provides all that the Permission needs.
// Returns true if the identity has all the permission needs.
func (p *permission) Requires(i Identity) bool {
	return i.Provides().Has(p.Needs().List()...)
}
