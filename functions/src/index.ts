import * as admin from 'firebase-admin';
import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";
import * as config from './config';

admin.initializeApp(config.firebaseConfig);

import * as CVEFunction from './CVE/index';
import * as SPLFunction from './SPL/index';
import * as bulletinFunction from './bulletin/index';
import * as androidVersionFunction from './Android Version/index';
import { error } from 'console';

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getCVEFunction = CVEFunction.getCVE;
export const getSPLFunction = SPLFunction.getSPL;
export const getBulletinFunction = bulletinFunction.getBulletin;
export const getAndroidVersionFunction = androidVersionFunction.getAndroidVersion;

export const getData = functions.https.onRequest(main)
let userToken: string = "";

app.post('/data', (request: any, response: any) => {
  if (request.body['email']){
    const email : string = request.body['email'];
    setAdminPriveleges(email).then(() => {
      response.send('admin_done');
    }).catch(error);
  } else if(request.body['userToken']){
    userToken = request.body['userToken'];
    admin.auth().verifyIdToken(userToken).then((claims) => {
      if (claims.isAdmin === true) {console.log('user is admin');}
      else { console.log('not admin');}
    }).catch(error);
  }
});

async function setAdminPriveleges(userEmail: string) : Promise<void> {
  const user = await admin.auth().getUserByEmail(userEmail);
  if (userEmail.split('@')[1] === 'google.com'){
    if (user.customClaims && (user.customClaims as any).isAdmin === true) {
      return;
    }
    return admin.auth().setCustomUserClaims(user.uid, {
      isAdmin: true,
      isPartner: false
    });
  }
}
