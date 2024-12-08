package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/kokizzu/rand"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	allowedOrigins, ok := os.LookupEnv("ALLOWED_ORIGINS")
	if !ok {
		allowedOrigins = "http://localhost:3000"
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{allowedOrigins},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           2599999999,
	}))
	googleClientId, ok := os.LookupEnv("GOOGLE_CLIENT_ID")
	if !ok {
		slog.Warn("GOOGLE_CLIENT_ID is not set")
	}
	googleClientSecret, ok := os.LookupEnv("GOOGLE_CLIENT_SECRET")
	if !ok {
		slog.Warn("GOOGLE_CLIENT_SECRET is not set")
	}
	googleLoginRedirect, ok := os.LookupEnv("GOOGLE_REDIRECT_URI_LOGIN")
	if !ok {
		slog.Warn("GOOGLE_REDIRECT_URI_LOGIN is not set")
	}
	googleRegisterRedirect, ok := os.LookupEnv("GOOGLE_REDIRECT_URI_REGISTER")
	if !ok {
		slog.Warn("GOOGLE_REDIRECT_URI_REGISTER is not set")
	}
	domain, ok := os.LookupEnv("DOMAIN")
	if !ok {
		slog.Warn("DOMAIN is not set")
	}
	var response struct {
		Message string `json:"message"`
	}
	r.Get("/login-request-url", func(w http.ResponseWriter, r *http.Request) {
		stateToken := randomString(32)
		cont := &oauth2.Config{
			ClientID:     googleClientId,
			ClientSecret: googleClientSecret,
			RedirectURL:  googleLoginRedirect,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
				"openid",
			},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "state-token",
			Value:    stateToken,
			Expires:  time.Now().Add(time.Minute * 10),
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: true,
			Domain:   domain,
		})
		googleURL := cont.AuthCodeURL(stateToken)
		render.Status(r, http.StatusOK)
		render.SetContentType(render.ContentTypeJSON)
		render.JSON(w, r, struct {
			Message string `json:"message"`
			URL     string `json:"url"`
		}{
			Message: "login",
			URL:     googleURL,
		})
	})
	r.Post("/login-post-callback", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code  string `json:"code"`
			State string `json:"state"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			slog.Error("Error decoding request body", slog.Any("error: ", err))
			render.Status(r, http.StatusInternalServerError)
			response.Message = "Internal server error"
			render.JSON(w, r, response)
			return
		}
		var validates []struct {
			Key     string `json:"key"`
			Message string `json:"message"`
		}
		if req.Code == "" {
			validates = append(validates, struct {
				Key     string `json:"key"`
				Message string `json:"message"`
			}{
				Key:     "code",
				Message: "Code is required",
			})
		}
		if req.State == "" {
			validates = append(validates, struct {
				Key     string `json:"key"`
				Message string `json:"message"`
			}{
				Key:     "state",
				Message: "State is required",
			})
		}
		if len(validates) > 0 {
			render.Status(r, http.StatusBadRequest)
			response.Message = "Bad request"
			render.JSON(w, r, response)
			return
		}
		stateToken, err := r.Cookie("state-token")
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			response.Message = fmt.Errorf("state-token cookie not found").Error()
			render.JSON(w, r, response)
			return
		}
		if stateToken.Value != req.State {
			render.Status(r, http.StatusBadRequest)
			response.Message = fmt.Errorf("state-token cookie value does not match").Error()
			render.JSON(w, r, response)
			return
		}
		cont := &oauth2.Config{
			ClientID:     googleClientId,
			ClientSecret: googleClientSecret,
			RedirectURL:  googleLoginRedirect,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
				"openid",
			},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		}
		token, err := cont.Exchange(r.Context(), req.Code)
		if err != nil {
			slog.Error("Error exchanging code", slog.Any("error: ", err))
			render.Status(r, http.StatusBadRequest)
			response.Message = "code not valid"
			render.JSON(w, r, response)
			return
		}
		idToken := token.Extra("id_token").(string)
		out, err := processLoginIDTOKEN(r.Context(), googleClientId, idToken)
		if err != nil {
			if errors.Is(err, errInvalidIDToken) {
				render.Status(r, http.StatusUnauthorized)
				response.Message = "invalid id token"
				render.JSON(w, r, response)
				return
			}
			if errors.Is(err, errUserNotFound) {
				slog.Info("User not found WRONG")
				render.Status(r, http.StatusUnauthorized)
				response.Message = "user not found"
				render.JSON(w, r, response)
				return
			}
			slog.Error("Error processing login id token", slog.Any("error: ", err))
			render.Status(r, http.StatusInternalServerError)
			response.Message = "Internal server error"
			render.JSON(w, r, response)
			return
		}
		if out.Message == "invalid email" {
			render.Status(r, http.StatusUnauthorized)
			response.Message = out.Message
			render.JSON(w, r, response)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "user-session",
			Value:    out.User.Session,
			Expires:  time.Now().Add(time.Hour * 72),
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: true,
			Domain:   domain,
		})
		render.Status(r, http.StatusOK)
		render.SetContentType(render.ContentTypeJSON)
		render.JSON(w, r, out)

	})
	r.Get("/register-request-url", func(w http.ResponseWriter, r *http.Request) {
		stateToken := randomString(32)
		cont := &oauth2.Config{
			ClientID:     googleClientId,
			ClientSecret: googleClientSecret,
			RedirectURL:  googleRegisterRedirect,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
				"openid",
			},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "state-token",
			Value:    stateToken,
			Expires:  time.Now().Add(time.Minute * 10),
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: true,
			Domain:   domain,
		})
		googleURL := cont.AuthCodeURL(stateToken)
		render.Status(r, http.StatusOK)
		render.SetContentType(render.ContentTypeJSON)
		render.JSON(w, r, struct {
			Message string `json:"message"`
			URL     string `json:"url"`
		}{
			Message: "register",
			URL:     googleURL,
		})
	})
	r.Post("/register-post-callback", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code  string `json:"code"`
			State string `json:"state"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			slog.Error("Error decoding request body", slog.Any("error: ", err))
			render.Status(r, http.StatusInternalServerError)
			response.Message = "Internal server error"
			render.JSON(w, r, response)
			return
		}
		var validates []struct {
			Key     string `json:"key"`
			Message string `json:"message"`
		}
		if req.Code == "" {
			validates = append(validates, struct {
				Key     string `json:"key"`
				Message string `json:"message"`
			}{
				Key:     "code",
				Message: "Code is required",
			})
		}
		if req.State == "" {
			validates = append(validates, struct {
				Key     string `json:"key"`
				Message string `json:"message"`
			}{
				Key:     "state",
				Message: "State is required",
			})
		}
		if len(validates) > 0 {
			render.Status(r, http.StatusBadRequest)
			response.Message = "Bad request"
			render.JSON(w, r, response)
			return
		}
		stateToken, err := r.Cookie("state-token")
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			response.Message = fmt.Errorf("state-token cookie not found").Error()
			render.JSON(w, r, response)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "state-token",
			Value:    "",
			Expires:  time.Now().Add(time.Second * -1),
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: true,
			Domain:   domain,
		})
		if stateToken.Value != req.State {
			render.Status(r, http.StatusBadRequest)
			response.Message = fmt.Errorf("state-token cookie value does not match").Error()
			render.JSON(w, r, response)
			return
		}
		cont := &oauth2.Config{
			ClientID:     googleClientId,
			ClientSecret: googleClientSecret,
			RedirectURL:  googleRegisterRedirect,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
				"openid",
			},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
		}
		token, err := cont.Exchange(r.Context(), req.Code)
		if err != nil {
			slog.Error("Error exchanging code", slog.Any("error: ", err))
			render.Status(r, http.StatusInternalServerError)
			response.Message = "Internal server error"
			render.JSON(w, r, response)
			return
		}
		idToken := token.Extra("id_token").(string)
		out, err := processRegisterIDTOKEN(r.Context(), googleClientId, idToken)
		if err != nil {
			if errors.Is(err, errInvalidEmail) {
				render.Status(r, http.StatusUnauthorized)
				response.Message = "invalid email"
				render.JSON(w, r, response)
				return
			}
			if errors.Is(err, errInvalidIDToken) {
				render.Status(r, http.StatusUnauthorized)
				response.Message = "invalid user"
				render.JSON(w, r, response)
				return
			}
			if errors.Is(err, errUserAlreadyExists) {
				render.Status(r, http.StatusConflict)
				response.Message = "User already exists"
				render.JSON(w, r, response)
				return
			}
			slog.Error("Error processing register id token", slog.Any("error: ", err))
			render.Status(r, http.StatusInternalServerError)
			response.Message = "Internal server error"
			render.JSON(w, r, response)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "user-session",
			Value:    out.User.Session,
			Expires:  time.Now().Add(time.Hour * 72),
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: true,
			Domain:   domain,
		})
		render.Status(r, http.StatusOK)
		render.SetContentType(render.ContentTypeJSON)
		render.JSON(w, r, out)
	})
	r.Get("/users", func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie("user-session")
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			response.Message = fmt.Errorf("user-session cookie not found").Error()
			render.JSON(w, r, response)
			return
		}
		for _, u := range users {
			if u.Session == session.Value {
				render.Status(r, http.StatusOK)
				render.SetContentType(render.ContentTypeJSON)
				render.JSON(w, r, u)
				return
			}
		}
		slog.Error("User not found", slog.Any("session: ", session.Value))
		render.Status(r, http.StatusNotFound)
		response.Message = "User not found"
		render.JSON(w, r, response)
	})
	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "9000"
	}

	slog.Info(fmt.Sprintf("Starting server on port http://localhost:%s", port))
	http.ListenAndServe(fmt.Sprintf(":%s", port), r)
}

type Out struct {
	Message string `json:"message"`
	User    User   `json:"user,omitempty"`
}

var (
	errUserNotFound      = errors.New("user not found")
	errInvalidIDToken    = errors.New("invalid id token")
	errInvalidEmail      = errors.New("invalid email")
	errUserAlreadyExists = errors.New("User already exists")
)

func processRegisterIDTOKEN(ctx context.Context, googleClientID, idToken string) (out Out, err error) {
	payload, err := idtoken.Validate(ctx, idToken, googleClientID)
	if err != nil {
		slog.Error("Error validating id token", slog.Any("error: ", err))
		err = errInvalidIDToken
		return
	}
	email, ok := payload.Claims["email"].(string)
	if !ok {
		slog.Error("Error getting email from id token", slog.Any("error: ", err))
		err = errInvalidEmail
		return
	}
	for _, u := range users {
		if u.Email == email {
			slog.Error("User already exists", slog.Any("email: ", email))
			err = errUserAlreadyExists
			return
		}
	}
	//regis the new user
	gname, _ := payload.Claims["given_name"].(string)

	//add the user to the list
	var user User
	user.Email = email
	user.Name = gname
	user.Session = randomString(32)
	users = append(users, user)

	//send the user back
	out.User.Email = email
	out.User.Name = gname
	return
}
func processLoginIDTOKEN(ctx context.Context, googeClientID, idToken string) (out Out, err error) {
	payload, err := idtoken.Validate(ctx, idToken, googeClientID)
	if err != nil {
		slog.Error("Error validating id token", slog.Any("error: ", err))
		err = errInvalidIDToken
		return
	}
	email, ok := payload.Claims["email"].(string)
	if !ok {
		out.Message = "invalid email"
		return
	}

	for _, u := range users {
		if u.Email == email {
			out.Message = "success"
			out.User.Email = email
			out.User.Name = u.Name
			out.User.Session = randomString(32)
			break
		}
	}
	if out.Message == "" {
		err = errUserNotFound
		slog.Info("User not found", slog.Any("email: ", email))
		return
	}
	return
}

type User struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Session string `json:"session"`
}

var users = []User{}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
