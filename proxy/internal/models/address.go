package models

type Address struct {
	City   string `json:"city" example:"Санкт-Петербург"`
	Street string `json:"street" example:"Московский"`
	House  string `json:"house" example:"14"`
	Lat    string `json:"lat" example:"59.923013"`
	Lon    string `json:"lon" example:"30.318105"`
}