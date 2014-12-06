package principal

import (
	"github.com/thrisp/flotilla"
	set "gopkg.in/fatih/set.v0"
)

type (
	Permission struct {
		Needs *set.Set
		//Excludes *set.Set
	}

	Identity struct {
		Id       string
		Provides *set.Set
	}

	Principal struct {
		c            *flotilla.Ctx
		loaders      []func(*flotilla.Ctx) *Identity
		handlers     []func(*Identity, *flotilla.Ctx)
		unauthorized flotilla.HandlerFunc
	}
)

func New(c ...Conf) *Principal {
	p := &Principal{}
	p.Configure(c...)
	return p
}

func (p *Principal) Init(app *flotilla.App) {
	app.Configuration = append(app.Configuration, flotilla.CtxFuncs(ctxfuncs(p)))
	app.UseAt(0, p.OnRequest)
}

func ctxfuncs(p *Principal) map[string]interface{} {
	ret := make(map[string]interface{})
	ret["principal"] = func() *Principal { return p }
	ret["currentidentity"] = func(c *flotilla.Ctx) *Identity { return currentidentity(c) }
	return ret
}

func (p *Principal) IdentityChange(i *Identity) {
	p.HandleIdentity(i)
}

func sessionloader(c *flotilla.Ctx) *Identity {
	identity := &Identity{}
	if iid := c.Session.Get("identity_id"); iid != nil {
		identity.Id = iid.(string)
	}
	return identity
}

func (p *Principal) LoadIdentity(c *flotilla.Ctx) *Identity {
	ret := &Identity{}
	for _, loader := range p.loaders {
		ret = loader(c)
	}
	p.HandleIdentity(ret)
	return ret
}

func sessionhandler(i *Identity, c *flotilla.Ctx) {
	c.Session.Set("identity_id", i.Id)
}

func (p *Principal) HandleIdentity(i *Identity) {
	for _, h := range p.handlers {
		h(i, p.c)
	}
	p.c.Set("identity", i)
}

func (p *Principal) OnRequest(c *flotilla.Ctx) {
	p.c = c
	p.LoadIdentity(c)
}

func NewPermission(needs ...interface{}) *Permission {
	return &Permission{Needs: set.New(needs...)}
}

// Allows checks the intersection of the permissions needs and the identity provides.
// Returns true is the intersection is not empty.
func (p *Permission) Allows(i *Identity) bool {
	return !set.Intersection(p.Needs, i.Provides).IsEmpty()
}

// Requires checks that given identity provides all that the Permission needs.
// Returns true if the identity has all the permission needs.
func (p *Permission) Requires(i *Identity) bool {
	return i.Provides.Has(p.Needs.List()...)
}

func NewIdentity(id string, provides ...interface{}) *Identity {
	return &Identity{Id: id, Provides: set.New(provides...)}
}

func (i *Identity) Can(p *Permission) bool {
	return p.Allows(i)
}

func (i *Identity) Must(p *Permission) bool {
	return p.Requires(i)
}

func currentidentity(c *flotilla.Ctx) *Identity {
	if identity := c.Data["identity"]; identity != nil {
		return identity.(*Identity)
	}
	return &Identity{}
}

// SufficientAuthorization wraps a flotilla HandlerFunc with permissions, allowing
// access to the handler if the current identity is allowed for any given permission.
func SufficientAuthorization(h flotilla.HandlerFunc, perms ...*Permission) flotilla.HandlerFunc {
	return func(c *flotilla.Ctx) {
		identity := currentidentity(c)
		permitted := false
		for _, p := range perms {
			if p.Allows(identity) {
				permitted = true
				h(c)
			}
		}
		if !permitted {
			p, _ := c.Call("principal")
			principal := p.(*Principal)
			if principal.unauthorized != nil {
				principal.unauthorized(c)
			} else {
				c.Status(401)
			}
		}
	}
}

// NecessaryAuthorization wraps a flotilla HandlerFunc with permissions, requiring
// that the current identity satifies all permissions fully before accessing the HandlerFunc.
func NecessaryAuthorization(h flotilla.HandlerFunc, perms ...*Permission) flotilla.HandlerFunc {
	return func(c *flotilla.Ctx) {
		identity := currentidentity(c)
		permitted := true
		for _, p := range perms {
			if !p.Requires(identity) {
				permitted = false
				p, _ := c.Call("principal")
				principal := p.(*Principal)
				if principal.unauthorized != nil {
					principal.unauthorized(c)
				} else {
					c.Status(401)
				}
			}
		}
		if permitted {
			h(c)
		}
	}
}
