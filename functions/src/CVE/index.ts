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
    const splID = request.query.splid;
    const splStart = request.query.splstart;
    const cveID = request.query.cveid;
    const spl1 = request.query.spl1;
    const spl2 = request.query.spl2;  
    const androidVersion = request.query.androidVersion;

    if (bulletinID){
      getCvesWithBulletinID(String(bulletinID),response);
    }
    else if (splID){
      getCvesWithSplID(String(splID),response);
    }
    else if (splStart){
      splStartHelper(String(splStart),response);
    } 
    else if (cveID){
      getCveWithCveID(String(cveID),response);
    }
    else if (spl1 && spl2){
      getChangesBetweenSPLs(String(spl1),String(spl2),response);
    }
    else if (androidVersion){
      getCvesWithAndroidVersion(String(androidVersion),response);
    }  

});

function getCvesWithBulletinID(id:string,res:any){
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
    res.status(400).send("error getting CVEs for bulletinID:"+ error);
  });
}

function getCvesWithSplID(id:string,res:any){
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
    res.status(400).send("error getting CVEs for spl:"+ error);
  });
}

//function SPLStartHelper(id)

function getCveWithCveID(id:any,res:any){
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.orderByKey().equalTo(id).once('value', function(snapshot) {
    const cveData = snapshot.val();
    res.send(cveData[id]);
  }).catch(error => {
    res.status(400).send("error getting details for CVEID:"+ error);
  });
}

function getChangesBetweenSPLs(id1:string,id2:string,res:any){
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
    const mergedCvelist = [].concat.apply([], splCves);
    const promises = [];
    for(const cve of mergedCvelist){
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
    const cvesBetweenSpls = {CVEs: cveList};
    res.send(cvesBetweenSpls);
  })
  .catch(error => {
    res.status(400).send("error getting cves between Spls: " + error)
  });
}

function getCvesWithAndroidVersion(version:string,res:any){
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
  
  allCvePromise.then((cves) => {
  const cveList = [];
  for (const cve of cves) {
    cveList.push(cve.val());
  }   
  res.send(JSON.stringify(cveList));
  })
  .catch(error => {
    res.status(400).send("error getting CVEs for AndroidVersion: " + error)
  });
}

function splStartHelper(id : string, res : any) : void {
  var db = admin.database();
  var ref = db.ref('/CVEs');

  ref.on("value", function(snapshot) {
    let cves = snapshot.val();
    let cve_array : Array<any> = [];
    const cve_jsons : any = Enumerable.from(cves)
      .where(function(obj) {return obj.value['ASB'] < id})
      .select(function (obj){
        return obj.value;})
  for (const cve of cve_jsons){
    cve_array.push(cve);
  }
  const result = {
    'CVEs' : cve_array
  }
  res.send(result);}, 
    function(error) { console.log(error);});
  }
