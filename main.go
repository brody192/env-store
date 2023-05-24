package main

import (
	"net/http"
	"time"

	"github.com/brody192/basiclogger"
	"github.com/brody192/bitsbytes"
	"github.com/brody192/ext/exthandler"
	"github.com/brody192/ext/extmiddleware"
	"github.com/brody192/ext/extutil"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"
)

func main() {
	var env, err = NewClient()
	if err == nil {
		basiclogger.InfoBasic.Println("redis connected successfully")
	} else if err != nil {
		basiclogger.Error.Fatal(err)
	}

	var r = chi.NewRouter()

	r.MethodNotAllowed(exthandler.MethodNotAllowedStatusText)

	r.Use(extmiddleware.AutoReply([]string{"/favicon.ico"}, 200))
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(extmiddleware.LimitBytes(bitsbytes.MegabytesToBytes[int64, int64](1)))
	r.Use(middleware.NoCache)
	r.Use(cors.AllowAll().Handler)

	r.Route("/env", func(r chi.Router) {
		r.Get("/user", env.GenUser)

		r.Group(func(r chi.Router) {
			r.Use(env.Auth)

			r.Post("/set", env.SetEnv)
			r.Get("/get", env.GetEnv)
			r.Get("/get-all", env.GetAllEnv)
			r.Delete("/delete", env.DelEnv)
		})
	})

	var port = extutil.EnvPortOr("3000")

	var s = &http.Server{
		Addr:              port,
		Handler:           r,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 1 * time.Second,
	}

	basiclogger.InfoBasic.Println("starting server on port " + port[1:])
	basiclogger.Error.Fatalln(s.ListenAndServe())
}
