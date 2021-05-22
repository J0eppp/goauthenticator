package main

import (
	"context"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"goauthenticator"
	"log"
	"net/http"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type User struct {
	Username string `json:"username" bson:"username"`
	Hash string `json:"hash" bson:"hash"`
	Salt string `json:"salt" bson:"salt"`
}

// The database structure contains all the information about the MongoDB database
type database struct {
	Client *mongo.Client
	Database *mongo.Database
	Ctx context.Context
}

func NewDatabase(uri string, ctx context.Context) (database, error) {
	var db database
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		return db, err
	}

	db.Ctx = ctx

	db.Client = client
	err = client.Connect(ctx)
	if err != nil {
		return db, err
	}

	db.Database = client.Database("goauthenticator")

	return db, nil
}

// Database functions

// GetUserPasswordAndSalt gets the hash and salt from the database corresponding to the users name
func (db *database) GetUserPasswordAndSalt(username string) (string, string, error) {
	var u User
	err := db.Database.Collection("users").FindOne(db.Ctx, bson.M{
		"username": username,
	}).Decode(&u)
	if err != nil {
		return "", "", err
	}

	log.Printf("%+v\n", u)

	return "", "", nil
}

func (db *database) GetSessionFromDatabase(sessionToken string) (goauthenticator.Session, error) {
	var session goauthenticator.Session
	err := db.Database.Collection("sessions").FindOne(db.Ctx, bson.M{
		"sessionToken": sessionToken,
	}).Decode(&session)
	return session, err
}

func (db *database) SaveSessionToDatabase(uid string, session goauthenticator.Session) error {
	//_, err := db.Database.Collection("sessions").UpdateOne(db.Ctx, bson.M{
	//	"username": uid,
	//}, bson.M{
	//	"$set": bson.M{"session": session},
	//})
	_, err := db.Database.Collection("sessions").InsertOne(db.Ctx, session)
	return err
}

func (db *database) SaveNewUser(u User) error {
	_, err := db.Database.Collection("users").InsertOne(db.Ctx, u)
	if err != nil {
		return err
	}
	return nil
}

var authenticator goauthenticator.Authenticator

func main() {
	db, err := NewDatabase("mongodb://localhost/goauthenticator", context.Background())
	if err != nil {
		panic(err)
	}

	log.Println("Connected to the database!")

	authenticator = goauthenticator.NewAuthenticator(db.GetSessionFromDatabase, db.SaveSessionToDatabase, "/login", 32, 10000, 64, db.GetUserPasswordAndSalt)

	router := mux.NewRouter().StrictSlash(false)

	router.HandleFunc("/get", getHandler)

	protectedRouter := router.Path("/").Subrouter()

	protectedRouter.Use(authenticator.SessionHandler.ValidateSession)
	
	protectedRouter.HandleFunc("/", indexHandler)


	log.Println("Webserver is running")
	log.Fatal(http.ListenAndServe(":8000", router))
}

// Protected route
func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi, I'm a protected route!")
}

// Session getter
func getHandler(w http.ResponseWriter, r *http.Request) {
	uid, ok := r.URL.Query()["uid"]
	if !ok {
		w.WriteHeader(400)
		fmt.Fprintf(w, "Bad Request, no uid GET parameter was found")
		return
	}

	session, err := authenticator.SessionHandler.CreateSession(uid[0])
	if err != nil {
		if !ok {
			w.WriteHeader(500)
			fmt.Fprintf(w, err.Error())
			return
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:       "sessionToken",
		Value:      session.SessionToken,
		Path:       "",
		Domain:     "",
		Expires:    time.Unix(session.Expires, 0),
		RawExpires: "",
		MaxAge:     0,
		Secure:     false,
		HttpOnly:   false,
		SameSite:   0,
		Raw:        "",
		Unparsed:   nil,
	})
	fmt.Fprintf(w, "Added cookie")
}