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
    const androidVersion = request.query.androidVersion;
    
    if (bulletinID !== null && bulletinID !== undefined){
      bulletinIDHelper(String(bulletinID),response);
    }
    else if (androidVersion !== null && androidVersion !== undefined){
      androidVersionHelper(String(androidVersion),response);
    }

});

function bulletinIDHelper(id:string, res:any){;
    const db = admin.database();
    const ref = db.ref('/Bulletin_SPL');
    let splData:any;
    ref.orderByKey().equalTo(id).once('value', function(snapshot) {
      splData = snapshot.val();
      const SPLs = {SPLs : splData[id]};
      res.send(SPLs);
    }).catch(error => {
      console.log("error getting spls for bulletinID: " + error)
    });
}

function androidVersionHelper(version:string, res:any){
    const db = admin.database();
    const ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
    let bulletinData:any;
    const aospVerToBulletinPromise = ref.orderByKey().equalTo(version).once('value')
    const bulletinSplPromise = aospVerToBulletinPromise.then((snapshot) => {
    bulletinData = snapshot.val();
    let promises = [];
    for(const bulletinID of Object.keys(bulletinData[version])){
      const splPromise = db.ref('/Bulletin_SPL').orderByKey().equalTo(bulletinID).once('value');
      promises.push(splPromise);
    }
    return Promise.all(promises);
    });
    bulletinSplPromise.then((bulletinSpls) => {
    const splArray = [];
    const bulletinIDs = Object.keys(bulletinData[version]);
    for (let i=0; i<bulletinSpls.length; i++){
      const bulletinSplObject = bulletinSpls[i].val();
      const spls = bulletinSplObject[bulletinIDs[i]];
      for (const spl of spls){
        splArray.push(spl);
      }
    }
    const SPLs = {SPLs: splArray};
    res.send(SPLs);
    }).catch(error => {
      console.log("error getting spls for AndroidVersion: " + error)
    });
}

