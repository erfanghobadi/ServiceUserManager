package main

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"log"
	"net/http"
	"time"
)

type User struct {
	ID         string `json:"id"`
	FirstName  string `json:"firstname"`
	LastName   string `json:"lastname"`
	Birthday   time.Time
	Email      string `json:"email"`
	Password   string `json:"password"`
	IsMale     bool   `json:"ismale"`
	NationalId string `json:"nationlid"`
	PhoneNumb  string `json:"phonenumber"`
}
type BirthdayUser struct {
	Year  int
	Month int
	Day   int
}

var user User
var secretKey = []byte("secret_key")
var collection *mongo.Collection

func main() {

	/// Connect to MongoDb...

	clientOption := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.Background(), clientOption)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	collection = client.Database("goDB").Collection("users")
	defer client.Disconnect(context.Background())
	///

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// main route...
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello Echo!")
	})
	e.POST("/signup", signUp)
	e.POST("/login", login)
	e.POST("/forget-password", forgetPassword)
	e.GET("/view-profile/:id", viewProfile)
	e.DELETE("/delete-user/:id", deleteUser)
	e.PUT("/change-password/:id", changePassword)
	e.PUT("/edit-profile/:id", editProfile)

	e.Start(":1379")
}

func hashPassword(userPass string) string {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userPass), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Failed generate hashed password..!", err)
	}
	userPass = string(hashedPassword)
	return userPass
}

func signUp(c echo.Context) error {
	if err := c.Bind(&user); err != nil {
		return err
	}

	// Check if the user already exists
	existingUser := User{}
	err := collection.FindOne(context.Background(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		return c.String(http.StatusBadRequest, "This email already exists..!")
	}
	///
	_, err = collection.InsertOne(context.Background(), user)
	if err != nil {
		fmt.Println("Signup new user failed..! ", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	/// Create token
	token := jwt.New(jwt.SigningMethodHS256)
	cliams := token.Claims.(jwt.MapClaims)
	cliams["id"] = user.ID
	cliams["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Server not response..!")
	}
	///
	return c.JSON(http.StatusOK, map[string]string{
		"token": tokenString,
	})
}

func login(c echo.Context) error {
	user.Password = c.FormValue("password")

	////// Find user from DB
	existingUser := User{}
	err := collection.FindOne(context.Background(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, "The email entered is incorrect..!")
	}

	/// Hash password then authentication
	c.Bind(user.Password)
	hashedPass := hashPassword(user.Password)
	if existingUser.Password != hashedPass {
		return err
	}
	///

	/// Create token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = existingUser.ID
	claims["exp"] = time.Now().Add(time.Hour * 2).Unix()

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "server not response..!")
	}
	///
	return c.JSON(http.StatusOK, map[string]string{
		"token": tokenString,
	})
}

func forgetPassword(c echo.Context) error {

	/// Find user from DB
	if err := c.Bind(&user); err != nil {
		return err
	}
	existingUser := User{}
	err := collection.FindOne(context.Background(), bson.M{"email": user.Email}).Decode(&existingUser)
	if err != nil {
		return c.String(http.StatusBadRequest, "This email not exists..!")
	}
	///

	/// Create reset link
	resetCode := uuid.New().String()
	resetLink := fmt.Sprintf("http://example.com/reset-password?code=%s", resetCode)
	///

	/// Send rest link to user email
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", "support@echo.go")
	mailer.SetHeader("To", user.Email)
	mailer.SetHeader("Subject", "Reset your password...")
	mailer.SetBody("text/plain", fmt.Sprintf("Click the blew link to rest your password:\n%s", resetLink))
	dialer := gomail.NewDialer("smtp.gmail.com", 587, "support@echo.go", "echo.email_password")
	if err := dialer.DialAndSend(mailer); err != nil {
		return err
	}
	///
	return c.JSON(http.StatusOK, "Recovery email sent.")
}
func viewProfile(c echo.Context) error {

	id := c.Param("id")
	if user.ID == "" {
		return c.JSON(http.StatusNotFound, "Id not found..!")
	}

	/// Find user from DB
	var result User
	err := collection.FindOne(context.Background(), bson.M{"id": id}).Decode(&result)
	if err != nil {
		return c.JSON(http.StatusNotFound, "User not found..!")
	}
	///

	return c.JSON(http.StatusOK, result)
}

func deleteUser(c echo.Context) error {

	id := c.Param("id")
	if id != "" {
		return c.JSON(http.StatusNotFound, "Id not found..!")
	}

	_, err := collection.DeleteOne(context.Background(), bson.M{"id": id})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Delete user failed..!")
	}

	return c.JSON(http.StatusOK, "Delete user successful.")
}

func changePassword(c echo.Context) error {

	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusNotFound, "Id not found..!")
	}
	newPassword := c.FormValue("newPassword")

	////// Checking user exist
	existingUser := User{}
	err := collection.FindOne(context.Background(), bson.M{"id": id}).Decode(&existingUser)
	if err != nil {
		return c.JSON(http.StatusNotFound, "User not found..!")
	}

	/// Hash password
	newPassword = hashPassword(newPassword)
	///

	filterId := bson.M{"id": id}
	updatePass := bson.M{"$set": bson.M{"password": newPassword}}
	_, err = collection.UpdateOne(context.Background(), filterId, updatePass)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Change password failed..!")
	}

	return c.JSON(http.StatusOK, "Change password successful.")
}

func editProfile(c echo.Context) error {

	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusNotFound, "Id not found..!")
	}
	/// Extracting edited user information
	if err := c.Bind(&user); err != err {
		return err
	}
	///

	////// Checking user exist
	var existingUser User
	filterId := bson.M{"id": id}
	err := collection.FindOne(context.Background(), filterId).Decode(&existingUser)
	if err != nil {
		return c.JSON(http.StatusNotFound, "User not found..!")
	}

	/// Hash password
	user.Password = hashPassword(user.Password)
	///

	/// Update data
	updateFields := bson.M{"set": user}
	_, err = collection.UpdateOne(context.Background(), filterId, updateFields)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Edit user failed..!")
	}
	///
	return c.JSON(http.StatusOK, "The changes were successful.")
}
