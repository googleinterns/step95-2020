import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as Enumerable from 'linq';
import deepEqual = require('deep-equal');
import * as checks from '../errorChecks';

export const getCVE = functions.https.onRequest((request, response) => {

  const bulletinID = request.query.bulletinid;
  const splID = request.query.splid;
  const splStart = request.query.splstart;
  const cveID = request.query.cveid;
  const spl1 = request.query.spl1;
  const spl2 = request.query.spl2;
  const androidVersion = request.query.androidVersion;
  const v1 = request.query.v1;
  const v2 = request.query.v2;

  if (bulletinID) {
    if (!checks.checkBulletinIDValidity(bulletinID)) {
      response.status(400).send('Bulletin ID is malformed.');
    } else {
      if (v1 && v2) {
        if (!checks.checkVersionIDValidity(v1) || !checks.checkVersionIDValidity(v2)) {
          response.status(400).send('Version ID is malformed.');
        } else {
          version1And2VulDifference(String(bulletinID), String(v1), String(v2), response);
        }
      } else {
        getCvesWithBulletinID(String(bulletinID), response);
      }
    }
  } else if (splID) {
    if (!checks.checkSPLValidity(splID)) {
      response.status(400).send('SPL ID is malformed.');
    } else {
      getCvesWithSplID(String(splID), response);
    }
  } else if (splStart) {
    if (!checks.checkSPLValidity(splStart)) {
      response.status(400).send('SPL ID is malformed.');
    } else {
      getCVEsBeforeSPL(String(splStart), response);
    }
  } else if (cveID) {
    if (!checks.checkCVEValidity(cveID)) {
      response.status(400).send('CVE ID is malformed.');
    } else {
      getCveWithCveID(String(cveID), response);
    }
  } else if (spl1 && spl2) {
    if (!checks.checkSPLValidity(spl1) || !checks.checkSPLValidity(spl2)) {
      response.status(400).send('SPL ID is malformed.');
    } else {
      getChangesBetweenSPLs(String(spl1), String(spl2), response);
    }
  } else if (androidVersion) {
    if (!checks.checkAndroidVersionValidity(androidVersion)) {
      response.status(400).send('Android Version ID is malformed.');
    } else {
      getCvesWithAndroidVersion(String(androidVersion), response);
    }
  } else {
    response.status(400).send('No valid parameters specified. Please specify a bulletin/spl/cve/android version.');
  }
});

function getCvesWithBulletinID(id: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/CVEs');
  const getCVEsPromise = ref.once('value');
  getCVEsPromise.then((snapshot) => {
    let cves = snapshot.val();
    cves = Enumerable.from(cves)
      .where(function (obj) { return obj.value.ASB === id })
      .select(function (obj) { return obj.value })
      .toArray();
    const result = { 'CVEs': cves };
    if (cves.length === 0) {
      throw new NotFoundError('There are no CVEs associated with this bulletin ID in the database.');
    }
    res.send(result);
  }).catch(error => {
    if (error instanceof NotFoundError) {
      res.status(404).send(error.message);
    } else {
      res.status(500).send('error getting CVEs for bulletinID:' + error);
    }
  });
}

function getCvesWithSplID(id: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/CVEs');
  const getCVEsPromise = ref.once('value');
  getCVEsPromise.then((snapshot) => {
    let cves = snapshot.val();
    cves = Enumerable.from(cves)
      .where(function (obj) { return obj.value.patch_level === id })
      .select(function (obj) { return obj.value })
      .toArray();
    const result = { 'CVEs': cves };
    if (cves.length === 0) {
      throw new NotFoundError('There are no CVEs associated with this SPL ID in the database.');
    }
    res.send(result);
  }).catch(error => {
    if (error instanceof NotFoundError) {
      res.status(404).send(error.message);
    } else {
      res.status(500).send('error getting CVEs for SPL:' + error);
    }
  });
}

function getCVEsBeforeSPL(id: string, res: any) {
  var db = admin.database();
  var ref = db.ref('/CVEs');
  const getCVEsPromise = ref.once('value');
  getCVEsPromise.then((snapshot) => {
    let cves = snapshot.val();
    let cve_array: Array<any> = [];
    const cve_jsons: any = Enumerable.from(cves)
      .where(function (obj) { return obj.value['ASB'] < id })
      .select(function (obj) {
        return obj.value;
      })
    for (const cve of cve_jsons) {
      cve_array.push(cve);
    }
    const result = {
      'CVEs': cve_array
    }
    if (cve_array.length === 0) {
      throw new NotFoundError('There are no CVEs associated with this SPL ID in the database.');
    }
    res.send(result);
  }).catch(error => {
    if (error instanceof NotFoundError) {
      res.status(404).send(error.message);
    } else {
      res.status(500).send('error getting CVEs with starting SPL:' + error);
    }
  });
}

function version1And2VulDifference(bulletin: string, version1: string, version2: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/CVE_History');
  const wholeVersion1 = bulletin + ':' + version1; //key is ASB:Version
  const wholeVersion2 = bulletin + ':' + version2;
  const version1And2Vul = ref.once('value');
  const version1And2FinalSet = version1And2Vul.then((snapshot) => {
    const cves = snapshot.val();
    const cves1 = Enumerable.from(cves) //get all cves of first version
      .where(function (obj) { return obj.value[wholeVersion1] !== undefined })
      .select(function (obj) { return obj.value[wholeVersion1] })
      .toArray();
    if (cves1.length === 0) {
      throw new NotFoundError('There are no CVEs associated with this bulletin ID and version in the database.');
    }
    const cves2 = Enumerable.from(cves) //get all cves of second version
      .where(function (obj) { return obj.value[wholeVersion2] !== undefined })
      .select(function (obj) { return obj.value[wholeVersion2] })
      .toArray();
    if (cves2.length === 0) {
      throw new NotFoundError('There are no CVEs associated with this bulletin ID and version in the database.');
    }
    const cves1Set = createSet(cves1); //create sets from arrays of cves
    const cves2Set = createSet(cves2);
    const cvesFinal = symmetricDifferenceBetweenSets(cves1Set, cves2Set);
    //find the difference between the two -> added or deleted cves

    const overlappingCVEs = intersectionBetweenSets(cves1Set, cves2Set);

    const cves1Map = new Map(cves1.map(x => [x.CVE, x]));
    const cves2Map = new Map(cves2.map(x => [x.CVE, x]));

    for (const element of overlappingCVEs) {
      if (!deepEqual(cves1Map.get(element), cves2Map.get(element))) {
        //if there has been any chnage to cve add to list
        cvesFinal.add(element);
      }
    }

    const promises = [];
    for (const cve of cvesFinal) {
      promises.push(cve);
    }
    return Promise.all(promises);
  })

  version1And2FinalSet.then((cvesFinalSet) => {
    const cveList = [];
    for (const cve of cvesFinalSet) {
      cveList.push(cve);
    }
    const result = { 'CVEs': cveList };
    res.send(result);
  }).catch(error => {
    if (error instanceof NotFoundError) {
      res.status(404).send(error.message);
    } else {
      res.status(500).send('Error getting CVEs for bulletin between v1 and v2: ' + error);
    }
  });
}

function createSet(data: any): Set<any> {
  const returnSet = new Set();
  for (const element of data) {
    returnSet.add(element.CVE);
  }
  return returnSet;
}


function symmetricDifferenceBetweenSets(setA: any, setB: any): Set<any> {
  const difference = new Set(setA)
  for (const element of setB) {
    if (difference.has(element)) {
      difference.delete(element)
    } else {
      difference.add(element)
    }
  }
  return difference;
}

function intersectionBetweenSets(setA: any, setB: any): Set<any> {
  const intersection = new Set();
  for (const element of setB) {
    if (setA.has(element)) {
      intersection.add(element);
    }
  }
  return intersection;

}

function getCveWithCveID(id: any, res: any) {
  const db = admin.database();
  const ref = db.ref('/CVEs');

  const getCVEsPromise = ref.orderByKey().equalTo(id).once('value');
  getCVEsPromise.then((snapshot) => {
    const cveData = snapshot.val();
    if (cveData === null || cveData === undefined) {
      throw new NotFoundError('CVE ID is not present in the database');
    }
    res.send(cveData[id]);
  }).catch(error => {
    if (error instanceof NotFoundError) {
      res.status(404).send(error.message);
    } else {
      res.status(500).send('error getting details for CVEID:' + error);
    }
  });
}

function getChangesBetweenSPLs(id1: string, id2: string, res: any) {
  let newSpl: string;
  let oldSpl: string;
  if (id1 > id2) {
    newSpl = id1;
    oldSpl = id2;
  }
  else {
    newSpl = id2;
    oldSpl = id1;
  }
  const db = admin.database();
  const ref = db.ref('/SPL_CVE_IDs');
  const splCvesPromise = ref.once('value');
  const cvePromise = splCvesPromise.then((snapshot) => {
    let splCves = snapshot.val();
    splCves = Enumerable.from(splCves)
      .where(function (obj) { return obj.key <= newSpl && obj.key > oldSpl })
      .select(function (obj) { return obj.value.CVE_IDs })
      .toArray();
    if (splCves.length === 0) {
      throw new NotFoundError('There are no CVEs between these two SPL IDs in the database.');
    }
    const mergedCvelist = [].concat.apply([], splCves);
    const promises = [];
    for (const cve of mergedCvelist) {
      const cveDataPromise = db.ref('/CVEs').orderByKey().equalTo(cve).once('value');
      promises.push(cveDataPromise);
    }
    return Promise.all(promises);
  })

  cvePromise.then((cves) => {
    const cveList = [];
    for (const cve of cves) {
      cveList.push(cve.val());
    }
    const cvesBetweenSpls = { CVEs: cveList };
    res.send(cvesBetweenSpls);
  }).catch(error => {
    if (error instanceof NotFoundError) {
      res.status(404).send(error.message);
    } else {
      res.status(500).send('error getting CVEs between SPLs: ' + error)
    }
  });
}

function getCvesWithAndroidVersion(version: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/AOSP_Version_CVE_IDs');
  let cveData: any;
  const aospVerToCvePromise = ref.orderByKey().equalTo(version).once('value');
  const allCvePromise = aospVerToCvePromise.then((snapshot) => {
    cveData = snapshot.val();
    if (cveData === null || cveData === undefined) {
      throw new NotFoundError('There are no CVEs associated with this Android Version in the database.');
    }
    const promises = [];
    for (const cveID of cveData[version]['CVE_IDs']) {
      const cvePromise = db.ref('/CVEs').orderByKey().equalTo(cveID).once('value');
      promises.push(cvePromise);
    }
    return Promise.all(promises);
  })

  allCvePromise.then((cves) => {
    const cveList = [];
    for (const cve of cves) {
      cveList.push(cve.val());
    }
    res.send({ CVEs: cveList });
  }).catch(error => {
    if (error instanceof NotFoundError) {
      res.status(404).send(error.message);
    } else {
      res.status(500).send('error getting CVEs for AndroidVersion: ' + error);
    }
  });
}

class NotFoundError extends Error { }