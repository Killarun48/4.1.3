package main

import (
	"encoding/json"
	"net/http"
)

type RequestRegisterLogin struct {
	Login    string `json:"login" example:"flip"`
	Password string `json:"password" example:"flop"`
}

type errorResponse struct {
	Message string `json:"message" example:"no token found"`
}

type ResponseRegister struct {
	ID string `json:"id" example:"999"`
}

type ResponseLogin struct {
	Token string `json:"token" example:"qpJhbGciOiJIUzI1NiIsInR5cCI6IlkXVCJ9.kaJsb2dpbiI6ImZsaXAifQ.N2Ycrfyww7I46L51y0MlofV2ef2iBVfsZaQ6J8EgOfk"`
}

func NewErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	errResponse := errorResponse{
		Message: message,
	}
	jsonResponse, _ := json.Marshal(errResponse)
	w.Write(jsonResponse)
}
