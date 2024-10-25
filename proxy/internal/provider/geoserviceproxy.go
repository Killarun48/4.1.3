package provider

import (
	"os"
	"test/internal/models"
)

type GeoServiceProxy struct {
	geoService *GeoService
}

func NewGeoServiceProxy() *GeoServiceProxy {
	apiKey := os.Getenv("API_KEY_GEO_SERVICE")
	secretKey := os.Getenv("SECRET_KEY_GEO_SERVICE")

	gs := NewGeoService(apiKey, secretKey)

	return &GeoServiceProxy{
		geoService: gs,
	}
}

func (gp *GeoServiceProxy) AddressSearch(input string) ([]*models.Address, error) {
	return gp.geoService.AddressSearch(input)
}

func (gp *GeoServiceProxy) GeoCode(lat, lng string) ([]*models.Address, error) {
	return gp.geoService.GeoCode(lat, lng)
}
