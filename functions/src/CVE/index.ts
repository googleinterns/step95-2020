import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";
import * as admin from 'firebase-admin';
import * as Enumerable from 'linq';

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getCVE = functions.https.onRequest(main);

app.get('/cves', (request, response) => {

  const bulletinID = request.query.bulletinid;
  const SPLID = request.query.splid;
  const SPLStart = request.query.splstart;
  const CVEID = request.query.cveid;
  const SPL1 = request.query.spl1;
  const SPL2 = request.query.spl2;  
  const androidVersion = request.query.androidVersion;

  if (bulletinID !== null && bulletinID !== undefined){
    bulletinIDHelper(String(bulletinID),response);
  }
  else if (SPLID !== null && SPLID !== undefined){
    SPLIDHelper(String(SPLID),response);
  }
  else if (SPLStart !== null && SPLStart !== undefined){
    //TODO: call helper function to query for spl start data 
  } 
  else if (CVEID !== null && CVEID !== undefined){
    CVEIDHelper(String(CVEID),response);
  }
  else if (SPL1 !== null && SPL2 !== null
    && SPL1 !== undefined && SPL2 !== undefined){
    SPL1and2Helper(String(SPL1),String(SPL2),response);
    }
  else if (androidVersion !== null && androidVersion !== undefined){
    androidVersionHelper(String(androidVersion),response);
  }

});

function SPLIDHelper(id:string,res:any){
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.once('value', function(snapshot) {
    let cves = snapshot.val();
    cves = Enumerable.from(cves)
    .where(function (obj) { return obj.value.patch_level === id })
    .select(function (obj) { return obj.value })
    .toArray();
    const result = {'CVEs': cves};
    res.send(result);
  }).catch(error => {
    console.log("error getting CVEs for spl:"+ error);
  });
}

function bulletinIDHelper(id:string,res:any){
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.once('value', function(snapshot) {
    let cves = snapshot.val();
    cves = Enumerable.from(cves)
    .where(function (obj) { return obj.value.ASB === id })
    .select(function (obj) { return obj.value })
    .toArray();
    const result = {'CVEs': cves};
    res.send(result);
  }).catch(error => {
    console.log("error getting CVEs for bulletinID:"+ error);
  });
}

//function SPLStartHelper(id)

function CVEIDHelper(id:any,res:any){
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.orderByKey().equalTo(id).once('value', function(snapshot) {
    const cveData = snapshot.val();
    res.send(cveData[id]);
  }).catch(error => {
    console.log("error getting details for CVEID:"+ error);
  });
}

function SPL1and2Helper(id1:any,id2:any,res:any){
  let newSpl: string;
  let oldSpl: string;
  if (id1 > id2){
    newSpl = id1;
    oldSpl = id2;
  }
  else{
    newSpl = id2;
    oldSpl = id1;
  }
  const db = admin.database();
  const ref = db.ref('/SPL_CVE_IDs');
  const splCvesPromise = ref.once('value');
  const cvePromise =  splCvesPromise.then((snapshot) => {
    let splCves = snapshot.val();
    splCves = Enumerable.from(splCves)
    .where(function (obj) { return obj.key <= newSpl && obj.key > oldSpl })
    .select(function (obj) { return obj.value.CVE_IDs })
    .toArray();
    const mergedCVElist = [].concat.apply([], splCves);
    const promises = [];
    for(const cve of mergedCVElist){
      const cveDataPromise = db.ref('/CVEs').orderByKey().equalTo(cve).once('value');
      promises.push(cveDataPromise);
    }
    return Promise.all(promises);
  })

  cvePromise.then((CVEs) => {
    const cveList = [];
    for (const cve of CVEs) {
      cveList.push(cve.val());
    }   
    const cvesBetweenSpls = {CVEs: cveList};
    res.send(cvesBetweenSpls);
  })
  .catch(error => {console.log("error getting cves between Spls: " + error)});
}

function androidVersionHelper(version:any,res:any){
  const db = admin.database();
  const ref = db.ref('/AOSP_Version_CVE_IDs');
  let cveData:any;
  const aospVerToCvePromise = ref.orderByKey().equalTo(version).once('value')
  const allCvePromise = aospVerToCvePromise.then((snapshot) => {
  cveData = snapshot.val();
  const promises = [];
  for(const cveID of cveData[version]["CVE_IDs"]){
    const cvePromise = db.ref('/CVEs').orderByKey().equalTo(cveID).once('value');
    promises.push(cvePromise);
  }
  return Promise.all(promises);
  })
  
  allCvePromise.then((CVEs) => {
  const cveList = [];
  for (const cve of CVEs) {
    cveList.push(cve.val());
  }   
  res.send(JSON.stringify(cveList));
  })
  .catch(error => {console.log("error getting CVEs for AndroidVersion: " + error)});
}