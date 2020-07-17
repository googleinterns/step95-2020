


# ASB API with cloud functions
## Introduction
Cloud Functions are about serverless event-driven code. Serverless applications have become increasingly popular in recent years. Serverless computing offers several advantages over traditional server-centric infrastructure: avoids the need for server provisioning, offers easier setup, greater scalability, more flexibility, and quicker time to release. With serverless architectures, developers can focus on writing and testing the application.

To build our RESTful API using serverless technology, we use RTDB (i.e. Firebase realtime database) and Firebase cloud functions, which can be wired to respond directly to HTTP requests.


## Table of Contents
* [Prerequisites](#Prerequisites)
* [Initialize project](#Initialize-project)
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

## Local testing
Run:
```sh
$ npm run lint
$ npm run build
$ firebase emulators:start
```
Check the output for the URL:

> http://localhost:5001/projectID/us-central1/ROUTE

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
$ curl https://step95-2020.firebaseapp.com/ROUTE -H "Authorization: bearer $(gcloud auth print-identity-token)"
```
