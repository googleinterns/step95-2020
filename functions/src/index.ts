import * as admin from 'firebase-admin';
import * as functions from 'firebase-functions';
import * as config from './config';

admin.initializeApp(config.firebaseConfig);

import * as CVEFunction from './CVE/index';
import * as SPLFunction from './SPL/index';
import * as bulletinFunction from './bulletin/index';
import * as androidVersionFunction from './Android Version/index';
import * as notificationFunction from './notification/index'; 
import * as uploadFunction from './upload/index';

export const getCVEFunction = CVEFunction.getCVE;
export const getSPLFunction = SPLFunction.getSPL;
export const getBulletinFunction = bulletinFunction.getBulletin;
export const getAndroidVersionFunction =
  androidVersionFunction.getAndroidVersion;

export const storeEmailFunction = notificationFunction.accountCreate;
export const notifyNewVersionFunction = notificationFunction.notifyNewVersion;
export const notifyNewReleaseFunction = notificationFunction.notifyNewRelease;

export const getUploadFunction = uploadFunction.getUpload;

export const grantAdminRole = functions.https.onRequest((request: any, response: any) => {
  if (request.headers['usertoken']) {
    admin.auth().verifyIdToken(String(request.headers['usertoken']))
      .then(function(decodedToken) {
        const email: any = decodedToken.email;
        setAdminPriveleges(email).catch(error => {
            response.status(400).send("Error giving admin privileges:"+ error);
        })
        if (decodedToken.isAdmin) { response.send("User has admin privileges");}
        else { response.send("User does not have admin privileges");}
      }).catch(error => {response.status(400).send("Error verifying token:" + error);}
    )
  }
})

async function setAdminPriveleges(userEmail: string): Promise<void> {
  const user = await admin.auth().getUserByEmail(userEmail);
  if (userEmail.split('@')[1] === 'google.com') {
    if (user.customClaims && (user.customClaims as any).isAdmin === true) {
      console.log('no admin');
      return;
    }
    console.log('admin');
    return admin.auth().setCustomUserClaims(user.uid, {
      isAdmin: true,
      isPartner: false,
    });
  }
}
