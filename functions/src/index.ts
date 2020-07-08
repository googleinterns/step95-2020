import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as express from 'express';
import * as bodyParser from "body-parser";

 const firebaseConfig = {
    apiKey: "AIzaSyBfQKMxa1azXidOZJjT8UYDm5BnU4s2bKA",
    authDomain: "step95-2020.firebaseapp.com",
    databaseURL: "https://step95-2020.firebaseio.com",
    projectId: "step95-2020",
    storageBucket: "step95-2020.appspot.com",
    messagingSenderId: "525367632678",
    appId: "1:525367632678:web:476053e80e5f22c6f417e7",
    measurementId: "G-QJE1CBXKGN"
  };
  // Initialize Firebase
admin.initializeApp(firebaseConfig);
//admin.initializeApp(functions.config().firebase);

const app = express();
const main = express();

main.use('/api/v1', app);
main.use(bodyParser.json());

export const webApi = functions.https.onRequest(main);

app.get('/warmup', (request, response) => {
    

    response.send('Warming up.');

});

