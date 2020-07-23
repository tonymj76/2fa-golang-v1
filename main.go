package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgryski/dgoogauth"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
)

var jwtSecret string

// //User model
type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type JwtToken struct {
	Token string `json:"token"`
}

type OtpToken struct {
	Token string `json:"otp"`
}

func SignJwt(claims jwt.MapClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func VerifyJwt(token string, secret string) (map[string]interface{}, error) {
	jwToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !jwToken.Valid {
		return nil, fmt.Errorf("Invalid authorization token")
	}
	return jwToken.Claims.(jwt.MapClaims), nil
}

func GetBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("An authorization header is required")
	}
	token := strings.Split(header, " ")
	if len(token) != 2 {
		return "", fmt.Errorf("Malformed bearer token")
	}
	return token[1], nil
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bearerToken, err := GetBearerToken(req.Header.Get("authorization"))
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}
		decodedToken, err := VerifyJwt(bearerToken, jwtSecret)
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}
		if decodedToken["authorized"] == true {
			context.Set(req, "decoded", decodedToken)
			next(w, req)
		} else {
			json.NewEncoder(w).Encode("2FA is required")
		}
	})
}

func CreateTokenEndpoint(w http.ResponseWriter, req *http.Request) {
	mockUser := make(map[string]interface{})
	mockUser["email"] = "user@gmail.com"
	mockUser["password"] = "password"
	mockUser["authorized"] = false
	tokenString, err := SignJwt(mockUser, jwtSecret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")
	json.NewEncoder(w).Encode(decoded)
}

func VerifyOtpEndpoint(w http.ResponseWriter, req *http.Request) {
	secret := "2MXGP5X3FVUEK6W4UB2PPODSP2GKYWUT"
	bearerToken, err := GetBearerToken(req.Header.Get("authorization"))
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	decodedToken, err := VerifyJwt(bearerToken, jwtSecret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}
	var otpToken OtpToken
	_ = json.NewDecoder(req.Body).Decode(&otpToken)
	decodedToken["authorized"], _ = otpc.Authenticate(otpToken.Token)
	if decodedToken["authorized"] == false {
		json.NewEncoder(w).Encode("Invalid one-time password")
		return
	}
	jwToken, _ := SignJwt(decodedToken, jwtSecret)
	json.NewEncoder(w).Encode(jwToken)
}

func GenerateSecretEndpoint(w http.ResponseWriter, req *http.Request) {
	random := make([]byte, 10)
	rand.Read(random)
	secret := base32.StdEncoding.EncodeToString(random)
	json.NewEncoder(w).Encode(secret)
}

func main() {
	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	jwtSecret = "JC7qMMZh4G"
	router.HandleFunc("/authenticate", CreateTokenEndpoint).Methods("POST")
	router.HandleFunc("/verify-otp", VerifyOtpEndpoint).Methods("POST")
	router.HandleFunc("/protected", ValidateMiddleware(ProtectedEndpoint)).Methods("GET")
	router.HandleFunc("/generate-secret", GenerateSecretEndpoint).Methods("GET")
	log.Fatal(http.ListenAndServe(":12345", router))
}
