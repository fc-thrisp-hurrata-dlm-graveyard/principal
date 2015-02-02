package principal

import (
	"github.com/thrisp/flotilla"
)

type (
	Conf func(*Manager) error
)

func (p *Manager) Configure(c ...Conf) error {
	var err error
	for _, fn := range c {
		err = fn(p)
	}
	if err != nil {
		return err
	}
	return nil
}

func UseSession() Conf {
	return func(p *Manager) error {
		p.loaders = append(p.loaders, sessionloader)
		p.handlers = append(p.handlers, sessionhandler)
		return nil
	}
}

func IdentityLoad(fns ...IdentityLoader) Conf {
	return func(p *Manager) error {
		p.loaders = append(p.loaders, fns...)
		return nil
	}
}

func IdentityHandle(fns ...IdentityHandler) Conf {
	return func(p *Manager) error {
		p.handlers = append(p.handlers, fns...)
		return nil
	}
}

func Unauthorized(fn flotilla.Manage) Conf {
	return func(p *Manager) error {
		p.unauthorized = fn
		return nil
	}
}
