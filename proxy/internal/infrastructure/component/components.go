package component

import (
	"test/internal/infrastructure/responder"
)

type Components struct {
	Responder responder.Responder
}

func NewComponents(responder responder.Responder) *Components {
	return &Components{Responder: responder}
}
