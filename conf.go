package principal

type (
	Conf func(*Principal) error
)

func (p *Principal) Configure(c ...Conf) error {
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
	return func(p *Principal) error {
		p.loaders = append(p.loaders, sessionloader)
		p.handlers = append(p.handlers, sessionhandler)
		return nil
	}
}
