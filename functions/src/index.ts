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

export const grantAdminRole = functions.https.onRequest(main);

app.post('/grantAdminRole', (request: any, response: any) => {
  if (request.body['userToken']) {
    admin.auth().verifyIdToken(request.body['userToken'])
      .then(function(decodedToken) {
        const email: any = decodedToken.email;
        setAdminPriveleges(email).catch(error => {
            response.status(400).send("Error giving admin privileges:"+ error);
        })
      }).catch(error => {response.status(400).send("Error verifiying token:" + error);}
    )
  }
});

async function setAdminPriveleges(userEmail: string): Promise<void> {
  const user = await admin.auth().getUserByEmail(userEmail);
  if (userEmail.split('@')[1] === 'google.com') {
    if (user.customClaims && (user.customClaims as any).isAdmin === true) {
      return;
    }
    console.log('User has been granted admin');
    return admin.auth().setCustomUserClaims(user.uid, {
      isAdmin: true,
      isPartner: false,
    });
  }
}
