import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';

export const grantAdminRole = functions.https.onRequest((request: any, response: any) => {
    if (request.headers['usertoken']) {
      admin.auth().verifyIdToken(String(request.headers['usertoken']))
        .then(function(decodedToken) {
          const email: any = decodedToken.email;
          var jsonResponse = null;
          setAdminPriveleges(email).catch(error => {
              response.status(400).send("Error giving admin privileges:"+ error);
          })
          if (decodedToken.isAdmin) { 
            jsonResponse = {"value": "User has admin privileges"};
          }
          else { 
           jsonResponse = {"value": "User does not have admin privileges"};
          }
          response.send(jsonResponse);
          return jsonResponse;
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
      return admin.auth().setCustomUserClaims(user.uid, {
        isAdmin: true,
        isPartner: false,
      });
    }
  }