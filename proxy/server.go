package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	//pprof2 "runtime/pprof"
	"syscall"
	"time"

	_ "test/docs"

	"test/internal/infrastructure/component"
	custommw "test/internal/infrastructure/middleware"
	"test/internal/infrastructure/responder"
	"test/internal/modules"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	"github.com/ptflp/godecoder"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

type Server struct {
	srv     *http.Server
	users   map[string]string
	sigChan chan os.Signal
}

func NewServer(addr string, hostProxy string, portProxy string) *Server {
	server := &Server{
		sigChan: make(chan os.Signal, 1),
		users:   make(map[string]string),
	}

	// добавляем стандартного пользователя
	hash, _ := bcrypt.GenerateFromPassword([]byte("flop"), 14)
	server.users["flip"] = string(hash)

	signal.Notify(server.sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	// Инициализируем маршруты
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	rp := custommw.NewReverseProxy(hostProxy, portProxy)
	r.Use(rp.ReverseProxy)

	logger, _ := zap.NewDevelopment()

	responder := responder.NewResponder(godecoder.NewDecoder(), logger)
	components := component.NewComponents(responder)
	services := modules.NewServices()

	c := modules.NewControllers(services, components)

	tokenAuth := jwtauth.New("HS256", []byte("gunmode"), nil)

	r.Post("/api/register", server.register)
	r.Post("/api/login", server.login)

	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)

		r.Route("/api/address", func(r chi.Router) {
			r.Post("/search", c.Geo.Search)
			r.Post("/geocode", c.Geo.Geocode)
		})

		r.Mount("/mycustompath", server.GetPprofRoutes())
	})

	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("doc.json"),
	))

	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	server.srv = srv
	return server
}

func (s *Server) Serve() {
	go func() {
		log.Println("Starting server...")
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-s.sigChan

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}

	log.Println("Server stopped gracefully")
}

func (s *Server) Stop() {
	s.sigChan <- syscall.Signal(1)
}

func (s *Server) GetPprofRoutes() *chi.Mux {

	r := chi.NewRouter()

	r.Get("/pprof", pprof.Index)

	r.Get("/pprof/allocs", pprof.Handler("allocs").ServeHTTP)
	r.Get("/allocs", pprof.Handler("allocs").ServeHTTP)

	r.Get("/pprof/block", pprof.Handler("block").ServeHTTP)
	r.Get("/block", pprof.Handler("block").ServeHTTP)

	r.Get("/pprof/cmdline", pprof.Handler("cmdline").ServeHTTP)
	r.Get("/cmdline", pprof.Handler("cmdline").ServeHTTP)

	r.Get("/pprof/goroutine", pprof.Handler("goroutine").ServeHTTP)
	r.Get("/goroutine", pprof.Handler("goroutine").ServeHTTP)

	r.Get("/pprof/heap", pprof.Handler("heap").ServeHTTP)
	r.Get("/heap", pprof.Handler("heap").ServeHTTP)

	r.Get("/pprof/mutex", pprof.Handler("mutex").ServeHTTP)
	r.Get("/mutex", pprof.Handler("mutex").ServeHTTP)

	//r.Get("/pprof/profile", pprof.Handler("profile").ServeHTTP)
	r.Get("/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("seconds") == "" {
			r.Form.Set("seconds", "10")
		}
		pprof.Profile(w, r)
	})

	r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("seconds") == "" {
			r.Form.Set("seconds", "10")
		}
		pprof.Profile(w, r)
	})

	r.Get("/pprof/threadcreate", pprof.Handler("threadcreate").ServeHTTP)
	r.Get("/threadcreate", pprof.Handler("threadcreate").ServeHTTP)

	//r.Get("/pprof/trace", pprof.Trace)
	r.Get("/pprof/trace", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("seconds") == "" {
			r.Form.Set("seconds", "10")
		}
		pprof.Trace(w, r)
	})
	r.Get("/trace", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("seconds") == "" {
			r.Form.Set("seconds", "10")
		}
		pprof.Trace(w, r)
	})

	r.Get("/debug/pprof/goroutine", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("debug") == "" {
			r.Form.Set("debug", "2")
		}
		pprof.Handler("goroutine").ServeHTTP(w, r)
	})

	return r
}

// @Summary Регистрация пользователя
// @Tags api
// @Accept json
// @Produce json
// @Param login,password body RequestRegisterLogin true "Учетные данные"
// @Success 200 {object} ResponseRegister
// @Failure 400,403 {object} errorResponse
// @Router /api/register [post]
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var body RequestRegisterLogin

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		NewErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 14)
	if err != nil {
		NewErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	s.users[body.Login] = string(hash)

	rand.Seed(time.Now().UnixNano())
	id := rand.Intn(100)

	responseRegister := ResponseRegister{ID: fmt.Sprint(id)}
	jsonResp, _ := json.Marshal(responseRegister)

	responseString := string(jsonResp)
	fmt.Fprint(w, responseString)
}

// @Summary Авторизация пользователя
// @Tags api
// @Accept json
// @Produce json
// @Param login,password body RequestRegisterLogin true "Учетные данные"
// @Success 200 {object} ResponseLogin
// @Failure 400,403 {object} errorResponse
// @Router /api/login [post]
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body RequestRegisterLogin

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		//NewErrorResponse(w, http.StatusBadRequest, err.Error())
		w.WriteHeader(http.StatusBadRequest)
		errResponse := errorResponse{
			Message: err.Error(),
		}
		jsonResponse, _ := json.Marshal(errResponse)
		w.Write(jsonResponse)
		return
	}

	if v, ok := s.users[body.Login]; ok {
		err := bcrypt.CompareHashAndPassword([]byte(v), []byte(body.Password))
		if err != nil {
			//NewErrorResponse(w, http.StatusOK, "неверный пароль")
			w.WriteHeader(http.StatusOK)
			errResponse := errorResponse{
				Message: "неверный пароль",
			}
			jsonResponse, _ := json.Marshal(errResponse)
			w.Write(jsonResponse)
			return
		}
	} else {
		//NewErrorResponse(w, http.StatusOK, "пользователь не найден")
		w.WriteHeader(http.StatusOK)
		errResponse := errorResponse{
			Message: "пользователь не найден",
		}
		jsonResponse, _ := json.Marshal(errResponse)
		w.Write(jsonResponse)
		return
	}

	tokenAuth := jwtauth.New("HS256", []byte("gunmode"), nil)
	_, tokenString, _ := tokenAuth.Encode(map[string]interface{}{"login": body.Login})

	responseLogin := ResponseLogin{Token: tokenString}
	jsonResp, _ := json.Marshal(responseLogin)

	responseString := string(jsonResp)

	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    tokenString,
		Path:     "/",
		Expires:  time.Now().Add(1 * time.Hour),
		HttpOnly: true,
		Secure:   false,
	})

	fmt.Fprint(w, responseString)
}
