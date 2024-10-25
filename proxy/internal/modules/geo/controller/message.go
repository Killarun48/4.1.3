package controller

import (
	"test/internal/models"
)

type RequestAddressSearch struct {
	Query string `json:"query" example:"Московский проспект 14"`
}

type ResponseAddress struct {
	Addresses []*models.Address `json:"addresses"`
}

type RequestAddressGeocode struct {
	Lat string `json:"lat" example:"59.923013"`
	Lng string `json:"lng" example:"30.318105"`
}
