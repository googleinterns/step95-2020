import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";
import * as admin from 'firebase-admin';

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getSPL = functions.https.onRequest(main);

app.get('/spls', (request, response) => {

  const bulletinID = request.query.bulletinid;
  const androidVersionID = request.query.androidVersion;

  if (bulletinID){
    getSplsWithBulletinID(String(bulletinID),response);
  }
  else if (androidVersionID){
    //androidVersionHelper(String(bulletinID),response);
  }

});

function getSplsWithBulletinID(id:string, res:any){;
  const db = admin.database();
  const ref = db.ref('/Bulletin_SPL');
  let splData:any;
  ref.orderByKey().equalTo(id).once('value', function(snapshot) {
    splData = snapshot.val();
    const SPLs = {SPLs : splData[id]}
    res.send(SPLs);
  }).catch(error => {
    res.send("error getting spls for bulletinID: " + error)
  });
}

// function androidVersionHelper(id){

// }

