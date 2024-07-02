package config

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/kv"
)

const defaultEndpoint = "integrations/geo-points-svc/v1/public/balances/"

type Points struct {
	URL string `fig:"url,required"`

	Endpoint        string `fig:"endpoint"`
	DefaultVerified bool   `fig:"default_verified"`
	Disabled        bool   `fig:"disabled"`
}

func (c *config) Points() *Points {
	return c.points.Do(func() interface{} {
		var cfg Points

		err := figure.Out(&cfg).
			From(kv.MustGetStringMap(c.getter, "points")).
			Please()
		if err != nil {
			panic(fmt.Errorf("failed to figure out points config: %w", err))
		}

		if !cfg.Disabled {
			err := validation.Errors{
				"points/url": validation.Validate(cfg.URL, validation.Required, is.URL),
			}.Filter()
			if err != nil {
				panic(err)
			}

			if cfg.Endpoint == "" {
				cfg.Endpoint = defaultEndpoint
			}
		}

		return &cfg
	}).(*Points)
}
