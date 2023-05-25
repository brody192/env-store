package main

import (
	"context"
	"main/client"
	"net/http"
	"os"
	"time"

	"github.com/brody192/basiclogger"
	"github.com/brody192/bitsbytes"
	"github.com/brody192/ext/exthandler"
	"github.com/brody192/ext/extmiddleware"
	"github.com/brody192/ext/extutil"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/rs/cors"
)

func main() {
	var rClient, err = client.NewRedisClient(os.Getenv("REDIS_URL"))
	if err == nil {
		basiclogger.InfoBasic.Println("redis connected successfully")
	} else if err != nil {
		basiclogger.Error.Fatal(err)
	}

	var env = &envHandler{
		ctx:   context.Background(),
		redis: rClient,
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

	var rateLimit1 = httprate.LimitByIP(1, 1*time.Second)
	var rateLimit2 = httprate.LimitByIP(2, 1*time.Second)

	r.Route("/env", func(r chi.Router) {
		r.With(rateLimit1).Get("/user", env.GenUser)

		r.Group(func(r chi.Router) {
			r.Use(rateLimit2)
			r.Use(env.Auth)

			r.Post("/set", env.SetEnv)
			r.Get("/get", env.GetEnv)
			r.Get("/get-all", env.GetAllEnv)
			r.Delete("/delete", env.DelEnv)
		})
	})

	exthandler.RegisterTrailing(r)

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
