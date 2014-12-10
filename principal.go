package principal

import (
	"github.com/thrisp/flotilla"
	set "gopkg.in/fatih/set.v0"
)

var (
	Anonymous = NewIdentity("anonymous", "anonymous")
)

type (
	IdentityLoader func(*flotilla.Ctx) *Identity

	IdentityHandler func(*Identity, *flotilla.Ctx)

	Permission struct {
		Needs *set.Set
		//Excludes *set.Set
	}

	Identity struct {
		Id       string
		Provides *set.Set
	}

	Manager struct {
		ctx          *flotilla.Ctx
		loaders      []IdentityLoader
		handlers     []IdentityHandler
		unauthorized flotilla.HandlerFunc
	}
)

func New(c ...Conf) *Manager {
	p := &Manager{}
	c = append(c, IdentityHandle(defaulthandler))
	p.Configure(c...)
	return p
}

func (m *Manager) Init(app *flotilla.App) {
	app.Configuration = append(app.Configuration, flotilla.CtxFuncs(ctxfuncs(m)))
	app.UseAt(0, m.OnRequest)
}

func ctxfuncs(m *Manager) map[string]interface{} {
	ret := make(map[string]interface{})
	ret["principal"] = func() *Manager { return m }
	ret["currentidentity"] = func(c *flotilla.Ctx) *Identity { return currentidentity(c) }
	return ret
}

func (m *Manager) Change(i *Identity) {
	m.Handle(i)
}

func sessionloader(c *flotilla.Ctx) *Identity {
	if iid := c.Session.Get("identity_id"); iid != nil {
		id := iid.(string)
		return NewIdentity(id, id)
	}
	return Anonymous
}

func (m *Manager) LoadIdentity(c *flotilla.Ctx) *Identity {
	identity := Anonymous
	for _, loader := range m.loaders {
		identity = loader(c)
	}
	m.Handle(identity)
	return identity
}

func defaulthandler(i *Identity, c *flotilla.Ctx) {
	c.Set("identity", i)
}

func sessionhandler(i *Identity, c *flotilla.Ctx) {
	c.Session.Set("identity_id", i.Id)
}

func (m *Manager) Handle(i *Identity) {
	for _, h := range m.handlers {
		h(i, m.ctx)
	}
}

func (m *Manager) OnRequest(c *flotilla.Ctx) {
	m.ctx = c
	m.LoadIdentity(c)
}

func (m *Manager) Unauthorized(c *flotilla.Ctx) {
	if m.unauthorized != nil {
		m.unauthorized(c)
	} else {
		c.Status(401)
	}
}

func NewPermission(needs ...interface{}) *Permission {
	return &Permission{Needs: set.New(needs...)}
}

func (p *Permission) Add(needs ...interface{}) {
	p.Needs.Add(needs...)
}

// Allows checks the intersection of the permissions needs and the identity provides.
// Returns true if the intersection is not empty.
func (p *Permission) Allows(i *Identity) bool {
	return !set.Intersection(p.Needs, i.Provides).IsEmpty()
}

// Requires checks that given identity provides all that the Permission needs.
// Returns true if the identity has all the permission needs.
func (p *Permission) Requires(i *Identity) bool {
	return i.Provides.Has(p.Needs.List()...)
}

func NewIdentity(id string, provides ...interface{}) *Identity {
	provides = append(provides, "anonymous")
	return &Identity{Id: id, Provides: set.New(provides...)}
}

func (i *Identity) Can(p *Permission) bool {
	return p.Allows(i)
}

func (i *Identity) Must(p *Permission) bool {
	return p.Requires(i)
}

func (i *Identity) Add(provides ...interface{}) {
	i.Provides.Add(provides...)
}

func currentidentity(c *flotilla.Ctx) *Identity {
	if identity := c.Data["identity"]; identity != nil {
		return identity.(*Identity)
	}
	return Anonymous
}

func manager(c *flotilla.Ctx) *Manager {
	p, _ := c.Call("principal")
	return p.(*Manager)
}

// Sufficient wraps a flotilla HandlerFunc with permissions, allowing
// access to the handler if the current identity is allowed for any given permission.
func Sufficient(h flotilla.HandlerFunc, perms ...*Permission) flotilla.HandlerFunc {
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
			manager(c).Unauthorized(c)
		}
	}
}

// Necessary wraps a flotilla HandlerFunc with permissions, requiring
// that the current identity satifies all permissions fully before accessing the HandlerFunc.
func Necessary(h flotilla.HandlerFunc, permissions ...*Permission) flotilla.HandlerFunc {
	return func(c *flotilla.Ctx) {
		identity := currentidentity(c)
		permitted := true
		for _, permission := range permissions {
			if !permission.Requires(identity) {
				permitted = false
				manager(c).Unauthorized(c)
			}
		}
		if permitted {
			h(c)
		}
	}
}
