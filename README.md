


# ASB API with cloud functions
## Introduction
Cloud Functions are about serverless event-driven code. Serverless applications have become increasingly popular in recent years. Serverless computing offers several advantages over traditional server-centric infrastructure: avoids the need for server provisioning, offers easier setup, greater scalability, more flexibility, and quicker time to release. With serverless architectures, developers can focus on writing and testing the application.

To build our RESTful API using serverless technology, we use RTDB (i.e. Firebase realtime database) and Firebase cloud functions, which can be wired to respond directly to HTTP requests.


## Table of Contents
* [Prerequisites](#Prerequisites)
* [Initialize project](#Initialize-project)
* [Routing with route params/query params](#Routing)
* [Triggering functions](#Triggering-functions)
* [Local testing](#Local-testing)
* [Deploy](#Deploy)

## Prerequisites
First, create a Firebase project in [Firebase console.](https://firebase.corp.google.com/)

We are going to be using node as well as express to host the server-side code and program in server-side Typescript. We also need to write functions locally with the help of firebase CLI. To set up the environment in Linux, follow these steps:

In Linux terminal, install nvm:
  ```sh
  $ curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | 
  ```
Restart Terminal once before starting using NVM.

Check in the terminal:
```sh
$ command -v nvm
```
> Sample output: nvm

Install Node.js and npm:
```sh
$ nvm install v12.18.1
```
Check in the terminal:
```sh
$ node --version
```
> Sample output: v12.18.1
```sh
$ npm --version
```
> Sample output: 6.14.5

Install Firebase CLI
```sh    
$ npm install -g firebase-tools
```
Can check its version
```sh
$ firebase --version
```

## Initialize project
In Linux terminal, run:
```sh
$ mkdir folderName
$ cd folderName/
$ firebase login 
```

> -> “Y” -> log in and allow access

```sh
$ firebase init
```

> Select “Database, Functions, Hosting, Emulators”   Select “Use an
> existing project” -> input projectID
> 
> Select Typescript
> 
> Type “Y” except “Configure as a single-page app (rewrite all urls to
> /index.html)?”
> 
> Select "Functions, Database, Hosting" for emulators

Should see ✔  Firebase initialization complete!

Then, run:
```sh
$ cd folderName/functions
$ npm install --save express body-parser
```

#### Directory Structure
There are three important things under the `functions` directory.
- `index.js` is a Javascript file where we define all the functions.
- `Package.json` is a Json file used by node, containing modules and their dependencies (e.g. Firebase Admin, Firebase functions) for the usage of the functions.
- `node_modules` is a folder where NPM installed those modules during the setup.

##### Change config file `firebase.json` as follows:
```sh
{
  ....
  "hosting": {
    "public": "public",
    "ignore": [
      "firebase.json",
      "**/.*",
      "**/node_modules/**"
    ],
    "rewrites": [
      {
        "source": "/api/v1/**",
        "function": "webApi"
      }
    ]
  }
}
```

##### Now, open `index.ts`:
#### Import main libraries
```sh
import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as express from 'express';
import * as bodyParser from "body-parser";
```
- Functions for Firebase SDK creates Cloud Functions and sets up triggers.
- Admin SDK provides access to FCM, - Authentication, and Firebase Realtime Database.
- Express is a web framework that manages routers and apps, and “app” is an instance of express.
- Cors handles cross domain requests.


#### Initialize firebase and Express.js server
```sh
admin.initializeApp(functions.config().firebase);
const app = express();
const main = express();
```
#### Configure the server
```sh
main.use('/api/v1', app);
main.use(bodyParser.json());
```
- '/api/v1' is the path for receiving the request
- bodyParser.json() sets JSON as the main parser for processing requests body

## Routing
#### Defining routes

The following route responds with “Hi!” on the homepage:

```sh
app.get('/warmup1', (req, res) => {
   const content = 'Hi!';
   res.send(content);
});
```

- ”app.get” corresponds to a GET request. It needs to be changed accordingly if it responds to other requests.

> See the result locally by going to this url: http://localhost:5001/projectID/us-central1/webApi/api/v1/warmup1
> 
> E.g. http://localhost:5001/step95-2020/us-central1/webApi/api/v1/warmup
> 
> Note: The port may be different on your local machine.


#### Query parameters
The following route takes query parameters from the request. With the query param specified in the url as shown below, the returned content is the same as (a).

```sh
app.get('/warmup2', (req, res) => {
   const content = req.query.text;
   res.send(content);
});
```
>Sample url: http://localhost:5001/step95-2020/us-central1/webApi/api/v1/warmup2?text=Hi!


#### Route parameters
The following route takes route parameters from the request, “/: text” in the path specifies the route parameter. With the route param specified in the url as shown below, the returned content is the same as (a).

```sh
app.get('/warmup3/:text', (req, res) => {
   const content = req.params.text;
   res.send(content);
});
```
>Sample url: http://localhost:5001/step95-2020/us-central1/webApi/api/v1/warmup3/Hi!

## Triggering functions

After defining the route, do:

```sh
export const webApi = functions.https.onRequest(main);
```

- functions.https creates a function that handles HTTP events. The event handler for an HTTP function listens for the onRequest() event, which supports routers and apps managed by the Express web framework.

#### Some notes:
Cloud Functions act as microservices that respond to various events.
Possible triggers that we may want to use:
| **Area**      | **JS representation** | **event handlers**    |
| :---        | :---        | :---         |
| HTTP      | functions.https       | onRequest   |
| Realtime Database    | functions.database.ref('path')        | onCreate, onUpdate, onDelete, onWrite    |
| Authentication   | functions.auth.user()       | onCreate, onDelete    |
| Pub/Sub   | functions.pubsub.topic('topic-name')        | onPublish    |

## Local testing
Run:
```sh
$ npm run lint
$ npm run build
$ firebase emulators:start
```
Check the output for the URL:

> http://localhost:5001/projectID/us-central1/webApi/api/v1/functionName
> 
> E.g. http://localhost:5001/step95-2020/us-central1/webApi/api/v1/warmup

Three different ways to check the output:

a. Use curl in the terminal

b. Enter the url in a browser

c. Use Postman

## Deploy
Run:
```sh
$ firebase deploy
```
Check the output for the URL:
```sh
$ curl https://step95-2020.firebaseapp.com/api/v1/warmup -H "Authorization: bearer $(gcloud auth print-identity-token)"
```
