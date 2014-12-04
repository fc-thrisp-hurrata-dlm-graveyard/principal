package principal

import (
	"github.com/thrisp/flotilla"
	set "gopkg.in/fatih/set.v0"
)

type (
	Permission struct {
		Needs    *set.Set
		Excludes *set.Set
	}

	Identity struct {
		Id       string
		Provides *set.Set
	}

	Principal struct {
		c              *flotilla.Ctx
		identitychange chan *Identity
		loaders        []func(*flotilla.Ctx) *Identity
		handlers       []func(*Identity)
		unauthorized   flotilla.HandlerFunc
	}
)

func New(c ...Conf) *Principal {
	p := &Principal{}
	p.identitychange = make(chan *Identity)
	p.Configure(c...)
	return p
}

func (p *Principal) Init(app *flotilla.App) {
	p.listen()
	app.Configuration = append(app.Configuration, flotilla.CtxFuncs(ctxfuncs(p)))
	app.UseAt(0, p.OnRequest)
}

func ctxfuncs(p *Principal) map[string]interface{} {
	ret := make(map[string]interface{})
	ret["principal"] = func() *Principal { return p }
	return ret
}

func (p *Principal) listen() {
	go func() {
		for {
			select {
			case i := <-p.identitychange:
				p.onchange(i)
			}
		}
	}()
}

func (p *Principal) IdentityChange(i *Identity) {
	p.identitychange <- i
}

func (p *Principal) onchange(i *Identity) {
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

func (p *Principal) sessionhandler(i *Identity) {
	p.c.Session.Set("identity_id", i.Id)
}

func (p *Principal) HandleIdentity(i *Identity) {
	for _, h := range p.handlers {
		h(i)
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

func (p *Permission) Allows(i *Identity) bool {
	return !set.Intersection(p.Needs, i.Provides).IsEmpty()
}

func NewIdentity(id string, provides ...interface{}) *Identity {
	return &Identity{Id: id, Provides: set.New(provides...)}
}

func (i *Identity) Can(p *Permission) bool {
	return p.Allows(i)
}

func PermissionsRequired(h flotilla.HandlerFunc, perms ...*Permission) flotilla.HandlerFunc {
	return func(c *flotilla.Ctx) {
		identity := c.Data["identity"].(*Identity)
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
