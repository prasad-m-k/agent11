package main

import "errors"

// Translator replaces sensitive values with surrogates (DPTP) so text can be
// sent onward without the originals. Only the interface exists today: the
// pipeline treats a translate verdict as block until a real Translator lands.
type Translator interface {
	Translate(text string) (string, error)
}

var errNoTranslator = errors.New("translation not implemented")

type noTranslator struct{}

func (noTranslator) Translate(string) (string, error) { return "", errNoTranslator }
