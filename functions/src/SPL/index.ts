import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as checks from '../errorChecks';

export const getSPL = functions.https.onRequest((request, response) => {

  const bulletinID = request.query.bulletinidSPL;
  const androidVersion = request.query.androidVersionSPL;

  if (bulletinID) {
    if (!checks.checkBulletinIDValidity(bulletinID)) {
      response.status(400).send('Bulletin ID is malformed.');
    }else{
      getSplsWithBulletinID(String(bulletinID), response);
    }
  }
  else if (androidVersion) {
    if (!checks.checkAndroidVersionValidity(androidVersion)) {
      response.status(400).send('Android Version ID is malformed.');
    }else{
      getSplsWithAndroidVersion(String(androidVersion), response);
    }
  }
  else{
    response.status(400).send('No valid parameters specified. Please specify a bulletin id/android version.');
  }

});

function getSplsWithBulletinID(id: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/Bulletin_SPL');
  let splData: any;
  const splsPromise = ref.orderByKey().equalTo(id).once('value');
  splsPromise.then((snapshot) => {
    splData = snapshot.val();
    if (splData === null || splData === undefined) {
      throw new NotFoundError('There is no SPL data associated with this bulletin in the database.');
    }
    const splOutput = { Spls: splData[id] }
    res.send(splOutput);
  }).catch(error => {
    if(error instanceof NotFoundError){
      res.status(404).send(error.message);
    }else{
      res.status(500).send('error getting SPLs for bulletinID:' + error);
    }
  });
}

function getSplsWithAndroidVersion(version: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
  let bulletinData: any;
  const aospVerToBulletinPromise = ref.orderByKey().equalTo(version).once('value');
  const bulletinSplPromise = aospVerToBulletinPromise.then((snapshot) => {
    bulletinData = snapshot.val();
    if (bulletinData === null || bulletinData === undefined) {
      throw new NotFoundError('There are no SPLs associated with this Android Version ID in the database.');
    }
    const promises = [];
    for (const bulletinID of Object.keys(bulletinData[version])) {
      const splPromise = db.ref('/Bulletin_SPL').orderByKey().equalTo(bulletinID).once('value');
      promises.push(splPromise);
    }
    return Promise.all(promises);
  });
  bulletinSplPromise.then((bulletinSpls) => {
    const splArray = [];
    const bulletinIDs = Object.keys(bulletinData[version]);
    for (let i = 0; i < bulletinSpls.length; i++) {
      const bulletinSplObject = bulletinSpls[i].val();
      const spls = bulletinSplObject[bulletinIDs[i]];
      for (const spl of spls) {
        splArray.push(spl);
      }
    }
    const splOutput = { Spls: splArray };
    res.send(splOutput);
  }).catch(error => {
    if(error instanceof NotFoundError){
      res.status(404).send(error.message);
    }else{
      res.status(500).send('error getting SPLs for AndroidVersion: ' + error);
    }
  });
}

class NotFoundError extends Error {}