import * as admin from 'firebase-admin';
import * as config from './config';

admin.initializeApp(config.firebaseConfig);

import * as CVEFunction from './CVE/index';
import * as SPLFunction from './SPL/index';
import * as bulletinFunction from './bulletin/index';
import * as androidVersionFunction from './Android Version/index';

export const getCVEFunction = CVEFunction.getCVE;
export const getSPLFunction = SPLFunction.getSPL;
export const getBulletinFunction = bulletinFunction.getBulletin;
export const getAndroidVersionFunction =
  androidVersionFunction.getAndroidVersion;

export const getData = functions.https.onRequest(main);

app.post('/data', (request: any, response: any) => {
  if (request.body['email']) {
    const email: string = request.body['email'];
    setAdminPriveleges(email).catch(error => {
        response.status(400).send("error giving admin privileges:"+ error);
      }
    )
  }
});

async function setAdminPriveleges(userEmail: string): Promise<void> {

  const user = await admin.auth().getUserByEmail(userEmail);
  if (userEmail.split('@')[1] === 'google.com') {
    if (user.customClaims && (user.customClaims as any).isAdmin === true) {
      return;
    }
    return admin.auth().setCustomUserClaims(user.uid, {
      isAdmin: true,
      isPartner: false,
    });
  }
}
