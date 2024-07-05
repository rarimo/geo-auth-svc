package hmacsig

import (
	"encoding/hex"
	"fmt"

	"gitlab.com/distributed_lab/figure/v3"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type SigCalculatorProvider interface {
	SigCalculator() Calculator
}

func NewCalculatorProvider(getter kv.Getter) SigCalculatorProvider {
	return &config{
		getter: getter,
	}
}

type config struct {
	getter kv.Getter
	once   comfig.Once
}

func (c *config) SigCalculator() Calculator {
	return c.once.Do(func() interface{} {
		var cfg struct {
			VerificationKey string `fig:"verification_key,required"`
		}

		err := figure.Out(&cfg).
			From(kv.MustGetStringMap(c.getter, "sig_verifier")).
			Please()
		if err != nil {
			panic(fmt.Errorf("failed to figure out sig_verifier: %w", err))
		}

		key, err := hex.DecodeString(cfg.VerificationKey)
		if err != nil {
			panic(fmt.Errorf("verification_key is not a hex: %w", err))
		}

		return NewCalculator(key)
	}).(Calculator)
}
