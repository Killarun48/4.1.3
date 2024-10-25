package service

import (
	"test/internal/models"
)

type GeoProvider interface {
	AddressSearch(input string) ([]*models.Address, error)
	GeoCode(lat, lon string) ([]*models.Address, error)
}

type GeoService struct {
	geoProvider GeoProvider
}

type GeoServicer interface {
	AddressSearch(input string) ([]*models.Address, error)
	GeoCode(lat, lng string) ([]*models.Address, error)
}

func NewGeoService(geoProvider GeoProvider) GeoServicer {
	return &GeoService{
		geoProvider: geoProvider,
	}
}

func (g *GeoService) AddressSearch(input string) ([]*models.Address, error) {
	return g.geoProvider.AddressSearch(input)
}

func (g *GeoService) GeoCode(lat, lng string) ([]*models.Address, error) {
	return g.geoProvider.GeoCode(lat, lng)
}
