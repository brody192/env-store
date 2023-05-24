package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/brody192/basiclogger"
	"github.com/brody192/ext/extrespond"
	"github.com/brody192/ext/extutil"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type envHandler struct {
	ctx   context.Context
	redis *redis.Client
}

type credentials struct {
	userId   string
	password string
}

type kvMap map[string]string

func (e *envHandler) GetCredentials(r *http.Request) *credentials {
	var userId = r.Header.Get("X-UserID")
	var password = r.Header.Get("X-Password")
	if userId == "" || password == "" {
		panic("userId or password not set")
	}
	return &credentials{
		userId:   userId,
		password: password,
	}
}

func (e *envHandler) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userId = r.Header.Get("X-UserID")
		if userId == "" {
			e.Error(w, "missing user id", http.StatusBadRequest)
			return
		}

		if _, err := uuid.Parse(userId); err != nil {
			e.Error(w, "Invalid user id", http.StatusBadRequest)
			return
		}

		var password = r.Header.Get("X-Password")
		if password == "" {
			e.Error(w, "missing password", http.StatusBadRequest)
			return
		}

		if utf8.RuneCountInString(password) < 8 {
			e.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		var i, err = e.redis.Exists(e.ctx, userId).Result()
		if err != nil {
			basiclogger.Error.Fatal("user lookup failure", err)
			e.Error(w, "user lookup failed", http.StatusInternalServerError)
			return
		}

		if i == 0 {
			e.Error(w, "user does not exist", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (e *envHandler) GenUser(w http.ResponseWriter, _ *http.Request) {
	var uuid = uuid.New().String()

	if err := e.redis.Set(e.ctx, uuid, nil, 0).Err(); err != nil {
		basiclogger.Error.Println("failed to create user =>", err)
		extrespond.PlainText(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	var resJson = map[string]string{
		"userId": uuid,
	}

	extrespond.JSON(w, resJson, http.StatusOK)
}

func (e *envHandler) SetEnv(w http.ResponseWriter, r *http.Request) {
	var reqBodyMap = kvMap{}

	if err := json.NewDecoder(r.Body).Decode(&reqBodyMap); err != nil {
		if errors.Is(err, io.EOF) {
			e.Error(w, "body json empty", http.StatusBadRequest)
			return
		}

		basiclogger.Error.Println(err)
		e.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(reqBodyMap) == 0 {
		extrespond.PlainText(w, "no new variables", http.StatusBadRequest)
		return
	}

	for k, v := range reqBodyMap {
		if utf8.RuneCountInString(k) > 128 {
			e.Error(w, "key length exceeds 128 characters", http.StatusBadRequest)
			return
		}

		if utf8.RuneCountInString(v) > 1024 {
			e.Error(w, "value length exceeds 1024 characters", http.StatusBadRequest)
			return
		}
	}

	if err := e.SetEnvRedis(e.GetCredentials(r), reqBodyMap); err != nil {
		if unAuth := e.HandleUnAuth(w, err); unAuth {
			return
		}

		basiclogger.Error.Println("failed to set redis data =>", err)
		e.Error(w, "failed to set redis data", http.StatusInternalServerError)
		return
	}

	extrespond.JSONString(w, "{}", http.StatusOK)
}

func (e *envHandler) GetEnv(w http.ResponseWriter, r *http.Request) {
	var variable = extutil.TrimmedQParam(r, "v")
	var variables = strings.Split(variable, ",")

	if len(variables) == 0 {
		e.Error(w, "no variables specified", http.StatusBadRequest)
		return
	}

	var resMap, err = e.GetEnvRedis(e.GetCredentials(r))
	if err != nil {
		if unAuth := e.HandleUnAuth(w, err); unAuth {
			return
		}

		basiclogger.Error.Println("failed to get redis data => ", err)
		e.Error(w, "failed to get redis data", http.StatusInternalServerError)
		return
	}

	if len(resMap) == 0 {
		extrespond.JSONString(w, "{}", http.StatusOK)
	}

	var newMap = kvMap{}

	for _, k := range variables {
		if v, ok := resMap[k]; ok {
			newMap[k] = v
		}
	}

	extrespond.JSON(w, newMap, http.StatusOK)
}

func (e *envHandler) DelEnv(w http.ResponseWriter, r *http.Request) {
	var variable = extutil.TrimmedQParam(r, "v")
	var variables = strings.Split(variable, ",")

	if len(variables) == 0 {
		e.Error(w, "no variables specified", http.StatusBadRequest)
		return
	}

	var resMap, err = e.GetEnvRedis(e.GetCredentials(r))
	if err != nil {
		if unAuth := e.HandleUnAuth(w, err); unAuth {
			return
		}

		basiclogger.Error.Println("failed to get redis data => ", err)
		e.Error(w, "failed to get redis data", http.StatusInternalServerError)
		return
	}

	if len(resMap) == 0 {
		extrespond.JSONString(w, "{}", http.StatusOK)
	}

	for _, k := range variables {
		delete(resMap, k)
	}

	if err := e.OverwriteEnvRedis(e.GetCredentials(r), resMap); err != nil {
		basiclogger.Error.Println("failed to set redis data =>", err)
		extrespond.PlainText(w, "failed to set redis data", http.StatusInternalServerError)
		return
	}

	extrespond.PlainText(w, http.StatusText(http.StatusOK), http.StatusOK)
}

func (e *envHandler) GetAllEnv(w http.ResponseWriter, r *http.Request) {
	var resMap, err = e.GetEnvRedis(e.GetCredentials(r))
	if err != nil {
		if unAuth := e.HandleUnAuth(w, err); unAuth {
			return
		}

		basiclogger.Error.Println("failed to get redis data => ", err)
		e.Error(w, "failed to get redis data", http.StatusInternalServerError)
		return
	}

	extrespond.JSON(w, resMap, http.StatusOK)
}

var ErrPasswordIncorrect = errors.New("password is incorrect")

func (e *envHandler) GetEnvRedis(creds *credentials) (kvMap, error) {
	var resMap = kvMap{}

	var resRedis, err = e.redis.Get(e.ctx, creds.userId).Bytes()
	if err != nil {
		return resMap, err
	}

	if len(resRedis) == 0 {
		return resMap, nil
	}

	decodedBytes, err := Decrypt([]byte(creds.password), resRedis)
	if err != nil {
		return resMap, ErrPasswordIncorrect
	}

	if err := gob.NewDecoder(bytes.NewReader(decodedBytes)).Decode(&resMap); err != nil {
		return resMap, err
	}

	return resMap, nil
}

func (e *envHandler) OverwriteEnvRedis(creds *credentials, newMap kvMap) error {
	var buf = &bytes.Buffer{}

	if err := gob.NewEncoder(buf).Encode(&newMap); err != nil {
		return err
	}

	var encodedBytes, err = Encrypt([]byte(creds.password), buf.Bytes())
	if err != nil {
		return err
	}

	if err := e.redis.Set(e.ctx, creds.userId, encodedBytes, 0).Err(); err != nil {
		return err
	}

	defer buf.Reset()

	return nil
}

func (e *envHandler) SetEnvRedis(creds *credentials, newMap kvMap) error {
	envMap, err := e.GetEnvRedis(creds)
	if err != nil {
		return err
	}

	for k, v := range newMap {
		envMap[k] = v
	}

	var buf = &bytes.Buffer{}

	if err := gob.NewEncoder(buf).Encode(&envMap); err != nil {
		return err
	}

	defer buf.Reset()

	encodedBytes, err := Encrypt([]byte(creds.password), buf.Bytes())
	if err != nil {
		return err
	}

	if err := e.redis.Set(e.ctx, creds.userId, encodedBytes, 0).Err(); err != nil {
		return err
	}

	return nil
}

func (e *envHandler) HandleUnAuth(w http.ResponseWriter, err error) bool {
	if errors.Is(err, ErrPasswordIncorrect) {
		e.Error(w, err.Error(), http.StatusUnauthorized)
		return true
	}

	return false
}

func (e *envHandler) Error(w http.ResponseWriter, message string, code int) {
	var resJson = map[string]any{
		"code":    code,
		"message": message,
	}

	extrespond.JSON(w, resJson, http.StatusBadRequest)
}