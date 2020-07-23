import * as admin from 'firebase-admin';
import * as express from 'express';
import * as bodyParser from "body-parser";
import * as functions from 'firebase-functions';
 
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
 
import * as CVEFunction from './CVE/index';
import * as SPLFunction from './SPL/index';
import * as bulletinFunction from './bulletin/index';
import * as androidVersionFunction from './Android Version/index';
 
const app = express();
const main = express();
// const fetch = require("node-fetch");
 
main.use(app);
main.use(bodyParser.json());
 
export const getCVEFunction = CVEFunction.getCVE;
export const getSPLFunction = SPLFunction.getSPL;
export const getBulletinFunction = bulletinFunction.getBulletin;
export const getAndroidVersionFunction = androidVersionFunction.getAndroidVersion;
 
export const getData = functions.https.onRequest(main);
const fs = require('fs');

app.post('/data', (request : any, response : any) => {
  var userToken = request.body['token'];
  if (userToken != 'error') {
  // console.log('token written into file' + userToken);
  fs.writeFile('userToken.txt', userToken, 'utf8', (error : any) => {
    if (error) throw error;
    console.log('User token has been successfully transfered!');
  }
  )} else {
    console.log('error trying to save user token');
  }
 })
 
