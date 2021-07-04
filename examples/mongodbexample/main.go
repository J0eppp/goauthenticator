package main

import (
	"context"
	"github.com/J0eppp/goauthenticator"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"

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

	protectedRouter := router.Path("/").Subrouter()

	protectedRouter.Use(authenticator.SessionHandler.ValidateSession)



	log.Println("Webserver is running")
	log.Fatal(http.ListenAndServe(":8000", router))
}