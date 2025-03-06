package main

import (
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/pquerna/otp/totp"
)

type User struct {
	Password string
	Secret   string
}

var (
	templates = template.Must(template.ParseGlob("templates/*.html"))
	users     = make(map[string]User)
)

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/generate-otp", generateOTPHandler)
	http.HandleFunc("/validate-otp", validateOTPHandler)

	log.Fatal(http.ListenAndServe(":4500", nil))
	log.Print("Server started running")
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == "GET" {
		err := templates.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")
	users["John"] = User{Password: "password", Secret: ""}
	user, ok := users[username]

	if !ok || user.Password != password {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func generateOTPHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve username from the query parameters
	username := r.URL.Query().Get("username")

	// Retrieve user details from the in-memory "database"
	user, ok := users[username]
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Generate TOTP secret if not already generated
	if user.Secret == "" {
		secret, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Go2FADemo",
			AccountName: username,
		})
		if err != nil {
			http.Error(w, "Failed to generate TOTP secret.", http.StatusInternalServerError)
			return
		}
		tempUser := user
		tempUser.Secret = secret.Secret()
		users[username] = tempUser
	}

	// Construct the OTP URL for generating QR code
	otpURL := fmt.Sprintf("otpauth://totp/Go2FADemo:%s?secret=%s&issuer=Go2FADemo", username, user.Secret)

	// Prepare data to pass to the template
	data := struct {
		OTPURL   string
		Username string
	}{
		OTPURL:   otpURL,
		Username: username,
	}

	// Render the qrcode.html template with the OTP URL data
	err := templates.ExecuteTemplate(w, "qrcode.html", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func validateOTPHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Retrieve the username from the query parameters
		username := r.URL.Query().Get("username")

		// Render the validate.html template, passing the username to it
		err := templates.ExecuteTemplate(w, "validate.html", struct{ Username string }{Username: username})
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}

	case "POST":
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		// Retrieve username and TOTP code from form data
		username := r.FormValue("username")
		otpCode := r.FormValue("otpCode")

		// Retrieve user details from the in-memory "database"
		user, exists := users[username]
		if !exists {
			http.Error(w, "User does not exist", http.StatusBadRequest)
			return
		}

		// Validate the TOTP code using the TOTP library
		isValid := totp.Validate(otpCode, user.Secret)
		if !isValid {
			// If validation fails, redirect back to the validation page
			http.Redirect(w, r, fmt.Sprintf("/validate-otp?username=%s", username), http.StatusTemporaryRedirect)
			return
		}

		// If validation succeeds, set a session cookie and redirect to the dashboard
		http.SetCookie(w, &http.Cookie{
			Name:   "authenticatedUser",
			Value:  "true",
			Path:   "/",
			MaxAge: 3600, // 1 hour for example
		})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the authenticated user's username from the session cookie
	username, err := r.Cookie("authenticatedUser")
	if err != nil || username.Value == "" {
		// If user is not authenticated, redirect to the homepage
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Render the dashboard.html template
	err = templates.ExecuteTemplate(w, "dashboard.html", nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
