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
      response.status(400).send("Error: Bulletin ID is malformed.");
    } if (v1 && v2) {
      if (!checks.checkVersionIDValidity(v1) || !checks.checkVersionIDValidity(v2)) {
        response.status(400).send("Error: Version ID is malformed.");
      }
      version1And2VulDifference(String(bulletinID), String(v1), String(v2), response);
    }
    getCvesWithBulletinID(String(bulletinID), response);
  }
  else if (splID) {
    if (!checks.checkSPLValidity(splID)) {
      response.status(400).send("Error: SPL ID is malformed.");
    }
    getCvesWithSplID(String(splID), response);
  }
  else if (splStart) {
    if (!checks.checkSPLValidity(splStart)) {
      response.status(400).send("Error: SPL ID is malformed.");
    }
    getCVEsBeforeSPL(String(splStart), response);

  }
  else if (cveID) {
    if (!checks.checkCVEValidity(cveID)) {
      response.status(400).send("Error: CVE ID is malformed.");
    }
    getCveWithCveID(String(cveID), response);

  }
  else if (spl1 && spl2) {
    if (!checks.checkSPLValidity(spl1) || !checks.checkSPLValidity(spl2)) {
      response.status(400).send("Error: SPL ID is malformed.");
    }
    getChangesBetweenSPLs(String(spl1), String(spl2), response);

  }
  else if (androidVersion) {
    if (!checks.checkAndroidVersionValidity(androidVersion)) {
      response.status(400).send("Error: Android Version ID is malformed.");
    }
    getCvesWithAndroidVersion(String(androidVersion), response);
  }
});

function getCvesWithBulletinID(id: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.once('value', function (snapshot) {
    let cves = snapshot.val();
    cves = Enumerable.from(cves)
      .where(function (obj) { return obj.value.ASB === id })
      .select(function (obj) { return obj.value })
      .toArray();
    const result = { 'CVEs': cves };
    if (cves.length === 0) {
      res.status(404).send("Error: There are no CVEs associated with this bulletin ID in the database.");
    }
    res.send(result);
  }).catch(error => {
    res.status(500).send("error getting CVEs for bulletinID:" + error);
  });
}

function getCvesWithSplID(id: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.once('value', function (snapshot) {
    let cves = snapshot.val();
    cves = Enumerable.from(cves)
      .where(function (obj) { return obj.value.patch_level === id })
      .select(function (obj) { return obj.value })
      .toArray();
    const result = { 'CVEs': cves };
    if (cves.length === 0) {
      res.status(404).send("Error: There are no CVEs associated with this SPL ID in the database.");
    }
    res.send(result);
  }).catch(error => {
    res.status(500).send("error getting CVEs for spl:" + error);
  });
}

function getCVEsBeforeSPL(id: string, res: any): void {
  var db = admin.database();
  var ref = db.ref('/CVEs');

  ref.on("value", function (snapshot) {
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
      res.status(404).send("Error: There are no CVEs associated with this SPL start ID in the database.");
    }
    res.send(result);
  },
    function (error) { res.status(500).send("Error getting cves with starting spl" + error); });
}

function version1And2VulDifference(bulletin: string, version1: string, version2: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/CVE_History');
  const wholeVersion1 = bulletin + ":" + version1;
  const wholeVersion2 = bulletin + ":" + version2;
  const version1And2Vul = ref.once('value');
  const version1And2FinalSet = version1And2Vul.then((snapshot) => {
    const cves = snapshot.val();
    const cves1 = Enumerable.from(cves)
      .where(function (obj) { return obj.value[wholeVersion1] !== undefined })
      .select(function (obj) { return obj.value[wholeVersion1] })
      .toArray();
    if (cves1.length === 0) {
      res.status(404).send("Error: There are no CVEs associated with this bulletin ID and version in the database.");
    }
    const cves2 = Enumerable.from(cves)
      .where(function (obj) { return obj.value[wholeVersion2] !== undefined })
      .select(function (obj) { return obj.value[wholeVersion2] })
      .toArray();
    if (cves2.length === 0) {
      res.status(404).send("Error: There are no CVEs associated with this bulletin ID and version in the database.");
    }
    const cves1Set = createSet(cves1);
    const cves2Set = createSet(cves2);

    const cvesFinal = symmetricDifferenceBetweenSets(cves1Set, cves2Set);

    const overlappingCVEs = intersectionBetweenSets(cves1Set, cves2Set);

    const cves1Map = new Map(cves1.map(x => [x.CVE, x]));
    const cves2Map = new Map(cves2.map(x => [x.CVE, x]));

    for (const element of overlappingCVEs) {
      if (!deepEqual(cves1Map.get(element), cves2Map.get(element))) {
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
  })
    .catch(error => { res.status(500).send("Error getting cves for bulletin between v1 and v2: " + error) });

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
  ref.orderByKey().equalTo(id).once('value', function (snapshot) {
    const cveData = snapshot.val();
    if (cveData === null || cveData === undefined) {
      res.status(404).send("Error: ID is not present in the database");
    }
    res.send(cveData[id]);
  }).catch(error => {
    res.status(500).send("error getting details for CVEID:" + error);
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
      res.status(404).send("Error: There are no CVEs between these two SPL IDs in the database.");
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
  })
    .catch(error => {
      res.status(500).send("error getting cves between Spls: " + error)
    });
}

function getCvesWithAndroidVersion(version: string, res: any) {
  const db = admin.database();
  const ref = db.ref('/AOSP_Version_CVE_IDs');
  let cveData: any;
  const aospVerToCvePromise = ref.orderByKey().equalTo(version).once('value')
  const allCvePromise = aospVerToCvePromise.then((snapshot) => {
    cveData = snapshot.val();
    if (cveData === null || cveData === undefined) {
      res.status(404).send("Error: There are no CVEs associated with this Android Version in the database.");
    }
    const promises = [];
    for (const cveID of cveData[version]["CVE_IDs"]) {
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
    res.send(JSON.stringify(cveList));
  })
    .catch(error => {
      res.status(500).send("error getting CVEs for AndroidVersion: " + error)
    });
}