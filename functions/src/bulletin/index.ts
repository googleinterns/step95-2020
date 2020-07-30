import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as checks from '../errorChecks';

export const getBulletin = functions.https.onRequest((request, response) => {

  const bulletinID = request.query.bulletinid;
  const androidVersion = request.query.androidVersion;

  if (bulletinID) {
    if (!checks.checkBulletinIDValidity(bulletinID)) {
      response.status(400).send('Bulletin ID is malformed.');
    }
    getSplsCvesWithBulletinID(String(bulletinID), response);
  }
  else if (androidVersion) {
    if (!checks.checkAndroidVersionValidity(androidVersion)) {
      response.status(400).send('Android Version ID is malformed.');
    }
    getSplsCvesWithAndroidVersion(String(androidVersion), response);
  }
  else{
    response.status(400).send('No valid parameters specified. Please specify a bulletin id/android version.');
  }

});

function getSplsCvesWithBulletinID(id: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/Bulletin_SPL');
  let splData: any;
  const bulletinToSplPromise = ref.orderByKey().equalTo(id).once('value');
  const allSplPromise = bulletinToSplPromise.then((snapshot) => {
    splData = snapshot.val();
    if (splData === null || splData === undefined) {
      throw new NotFoundError('There are no SPLs associated with this bulletin in the database.');
    }
    const promises = [];
    for (const spl of splData[id]) {
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
      if(error instanceof NotFoundError){
        res.status(404).send(error.message);
      }else{
        res.status(500).send('error getting details for bulletinID: ' + error);
      }
    });
}

function getSplsCvesWithAndroidVersion(version: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
  let bulletinData: any;
  const aospVerToBulletinPromise = ref.orderByKey().equalTo(version).once('value');
  const bulletinSplPromise = aospVerToBulletinPromise.then((snapshot) => {
    bulletinData = snapshot.val();
    if (bulletinData === null || bulletinData === undefined) {
      throw new NotFoundError('There are no SPL and CVE IDs associated with this bulletin in the database.');
    }
    const promises = [];
    for (const bulletinID of Object.keys(bulletinData[version])) {
      const spl = db.ref('/Bulletin_SPL').orderByKey().equalTo(bulletinID).once('value');
      promises.push(spl);
    }
    return Promise.all(promises);
  });

  const splPromise = bulletinSplPromise.then((bulletinSpls) => {
    const splArray = [];
    const bulletinIDs = Object.keys(bulletinData[version]);
    for (let i = 0; i < bulletinSpls.length; i++) {
      const bulletinSplObject = bulletinSpls[i].val();
      const spls = bulletinSplObject[bulletinIDs[i]];
      for (const spl of spls) {
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
    if(error instanceof NotFoundError){
      res.status(404).send(error.message);
    }else{
      res.status(500).send('error getting spls and cveIDs for AndroidVersion: ' + error);
    }
  });
}

class NotFoundError extends Error {}