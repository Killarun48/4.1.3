package modules

import (
	"net/http"
	"test/internal/infrastructure/component"
	"test/internal/modules/geo/controller"
)

type GeoController interface {
	Search(w http.ResponseWriter, r *http.Request)
	Geocode(w http.ResponseWriter, r *http.Request)
}

type Controllers struct {
	Geo GeoController
}

func NewControllers(services *Services, components *component.Components) *Controllers {
	geoController := controller.NewGeoController(services.Geo, components.Responder)
	
	return &Controllers{
		Geo: geoController,
	}
}
