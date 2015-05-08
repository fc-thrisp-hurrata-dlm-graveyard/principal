package principal

import (
	"reflect"

	"github.com/thrisp/flotilla"
)

type Manager struct {
	DataStore
	ctx          flotilla.Ctx
	loaders      []IdentityLoader
	handlers     []IdentityHandler
	unauthorized flotilla.Manage
}

func New(c ...Conf) *Manager {
	p := &Manager{}
	c = append(c, IdentityHandle(defaulthandler))
	p.Configure(c...)
	if p.DataStore == nil {
		p.DataStore = DefaultDataStore()
	}
	return p
}

func (m *Manager) Init(app *flotilla.App) {
	app.Configuration = append(app.Configuration, flotilla.Extensions(PrincipalFxtension(m)))
	app.UseAt(0, m.OnRequest)
}

type principalfxtension struct {
	fns map[string]reflect.Value
}

func (fx *principalfxtension) add(name string, fn interface{}) {
	fx.fns[name] = reflect.ValueOf(fn)
}

func PrincipalFxtension(m *Manager) flotilla.Fxtension {
	pf := &principalfxtension{fns: make(map[string]reflect.Value)}
	pf.add("principal", func(c flotilla.Ctx) *Manager { return m })
	pf.add("currentidentity", func(c flotilla.Ctx) Identity { return currentidentity(c) })
	return pf
}

func (p *principalfxtension) Name() string {
	return "fxprincipal"
}

func (p *principalfxtension) Set(rv map[string]reflect.Value) {
	for k, v := range p.fns {
		rv[k] = v
	}
}

func (m *Manager) Change(i Identity) {
	m.Handle(i)
}

func (m *Manager) LoadIdentity(c flotilla.Ctx) Identity {
	identity := Anonymous
	for _, loader := range m.loaders {
		identity = loader(c)
	}
	m.Handle(identity)
	return identity
}

func (m *Manager) Handle(i Identity) {
	for _, h := range m.handlers {
		h(i, m.ctx)
	}
}

func (m *Manager) OnRequest(c flotilla.Ctx) {
	m.ctx = c
	m.LoadIdentity(c)
}

func (m *Manager) Unauthorized(c flotilla.Ctx) {
	if m.unauthorized != nil {
		m.unauthorized(c)
	} else {
		c.Call("status", 401)
	}
}

func manager(c flotilla.Ctx) *Manager {
	p, _ := c.Call("principal")
	return p.(*Manager)
}

// Sufficient wraps a flotilla HandlerFunc with permissions, allowing
// access if the current identity is allowed for any given permission.
func Sufficient(h flotilla.Manage, perms ...Permission) flotilla.Manage {
	return func(c flotilla.Ctx) {
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
// that the current identity satifies all permissions fully before access.
func Necessary(h flotilla.Manage, permissions ...Permission) flotilla.Manage {
	return func(c flotilla.Ctx) {
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
