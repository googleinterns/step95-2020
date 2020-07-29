import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";
import * as admin from 'firebase-admin';

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getBulletin = functions.https.onRequest(main);

app.post('/bulletins', (request, response) => {

  const bulletinID = request.query.bulletinidBULLETIN;
  const androidVersion = request.query.androidVersionBULLETIN;

  if (bulletinID){
    getSplsCvesWithBulletinID(String(bulletinID),response);
  }
  else if (androidVersion){
    getSplsCvesWithAndroidVersion(String(androidVersion),response);
  }

});

function getSplsCvesWithBulletinID(id:string,res:any){
  const db = admin.database();
  const ref = db.ref('/Bulletin_SPL');
  let splData:any;
  const bulletinToSplPromise = ref.orderByKey().equalTo(id).once('value');
  const allSplPromise = bulletinToSplPromise.then((snapshot) => {
    splData = snapshot.val();
    const promises = [];
    for(const spl of splData[id] ){
        const splPromise = db.ref('/SPL_CVE_IDs').orderByKey().equalTo(spl).once('value');
        promises.push(splPromise);
    }
    return Promise.all(promises);
  })

  allSplPromise.then((splCveIDs) => {
    const splCveIDList = [];
    for (const splCveID of splCveIDs) {
        splCveIDList.push(splCveID.val());
    }   
    const output = {
        BulletinID: id,
        SplList: splCveIDList
    }
    res.send(JSON.stringify(output));
  })
  .catch(error => {
    res.status(400).send("error getting details for bulletinID: " + error)
  });
}

function getSplsCvesWithAndroidVersion(version:string,res:any){
  const db = admin.database();
  const ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
  let bulletinData:any;
  const aospVerToBulletinPromise = ref.orderByKey().equalTo(version).once('value')
  const bulletinSplPromise = aospVerToBulletinPromise.then((snapshot) => {
    bulletinData = snapshot.val();
    const promises = [];
    for(const bulletinID of Object.keys(bulletinData[version])){
        const spl = db.ref('/Bulletin_SPL').orderByKey().equalTo(bulletinID).once('value');
        promises.push(spl);
    }
    return Promise.all(promises);
  });

  const splPromise = bulletinSplPromise.then((bulletinSpls) => {
    const splArray = [];
    const bulletinIDs = Object.keys(bulletinData[version]);
    for (let i=0; i<bulletinSpls.length; i++){
        const bulletinSplObject = bulletinSpls[i].val();
        const spls = bulletinSplObject[bulletinIDs[i]];
        for (const spl of spls){
            splArray.push(spl);
        }
    }
    return splArray;
  });

  const splCvePromise = splPromise.then((splArray) => {
    const promises = [];
    for (const spl of splArray) {
    const splCve = db.ref('/SPL_CVE_IDs').orderByKey().equalTo(spl).once('value');
    promises.push(splCve);
    }
    return Promise.all(promises);
  });

  splCvePromise.then((splCveArray) => {
    const splCveIDList = [];
    for (const splCveID of splCveArray) {
      splCveIDList.push(splCveID.val());
    }   
    const output = {
      AndroidVersion: version,
      SplList: splCveIDList
    }
    res.send(JSON.stringify(output));
  }).catch(error => {
    res.status(400).send("error getting spls and cveIDs for AndroidVersion: " + error)
  });
}