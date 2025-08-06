package config

import (
	"fmt"
)

// Profiles are the profiles served by this contravider.
type Profiles map[string][]string

// UnmarshalTOML implements [toml.Unmarshaler].
func (p *Profiles) UnmarshalTOML(data any) error {

	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("unexpected type %T", data)
	}

	pr := make(Profiles, len(m))

	for k, v := range m {
		l, ok := v.([]any)
		if !ok {
			return fmt.Errorf("unexpected type %T", v)
		}
		list := make([]string, 0, len(l))
		for _, s := range l {
			str, ok := s.(string)
			if !ok {
				return fmt.Errorf("unexpected type %T", s)
			}
			list = append(list, str)
		}
		pr[k] = list
	}
	if err := pr.check(); err != nil {
		return err
	}
	*p = pr
	return nil
}

func (p Profiles) check() error {
	// TODO: check if all are defined, cyclic checks.
	return nil
}
