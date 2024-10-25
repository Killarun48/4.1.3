package controller

import (
	"encoding/json"
	"net/http"
	"test/internal/models"
)

type Responder interface {
	OutputJSON(w http.ResponseWriter, responseData interface{})

	ErrorUnauthorized(w http.ResponseWriter, err error)
	ErrorBadRequest(w http.ResponseWriter, err error)
	ErrorForbidden(w http.ResponseWriter, err error)
	ErrorInternal(w http.ResponseWriter, err error)
}

type GeoServicer interface {
	AddressSearch(input string) ([]*models.Address, error)
	GeoCode(lat, lng string) ([]*models.Address, error)
}

type GeoController struct {
	responder  Responder
	geoService GeoServicer
}

func NewGeoController(geoService GeoServicer, responder Responder) *GeoController {
	return &GeoController{
		responder:  responder,
		geoService: geoService,
	}
}

// @Summary Геокодирование (координаты по адресу)
// @Security ApiKeyAuth
// @Tags api
// @Accept json
// @Produce json
// @Param query body RequestAddressSearch true "Адрес"
// @Success 200 {object} ResponseAddress
// @Failure 400,403 {object} responder.Response
// @Router /api/address/search [post]
func (c *GeoController) Search(w http.ResponseWriter, r *http.Request) {
	var body RequestAddressSearch

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		c.responder.ErrorBadRequest(w, err)
		return
	}

	resp, err := c.geoService.AddressSearch(body.Query)
	if err != nil {
		c.responder.ErrorBadRequest(w, err)
		return
	}

	c.responder.OutputJSON(w, ResponseAddress{
		Addresses: resp,
	})
}

// @Summary Обратное геокодирование (адрес по координатам)
// @Security ApiKeyAuth
// @Tags api
// @Accept json
// @Produce json
// @Param lat,lng body RequestAddressGeocode true "Координаты. lat - Географическая широта. lng - Географическая долгота."
// @Success 200 {object} ResponseAddress
// @Failure 400,403 {object} responder.Response
// @Router /api/address/geocode [post]
func (c *GeoController) Geocode(w http.ResponseWriter, r *http.Request) {
	var body RequestAddressGeocode

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		c.responder.ErrorBadRequest(w, err)
		return
	}

	resp, err := c.geoService.GeoCode(body.Lat, body.Lng)
	if err != nil {
		c.responder.ErrorBadRequest(w, err)
		return
	}

	c.responder.OutputJSON(w, ResponseAddress{
		Addresses: resp,
	})
}
