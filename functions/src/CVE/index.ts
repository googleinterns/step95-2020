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
      //TODO: call helper function for data in between spls
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
  }).catch(error => {console.log(error)});
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
  }).catch(error => {console.log(error)});
}

//function SPLStartHelper(id)

function CVEIDHelper(id:any,res:any){
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.orderByKey().equalTo(id).once('value', function(snapshot) {
    const cveData = snapshot.val();
    res.send(cveData[id]);
  }).catch(error => {console.log(error)});
}

//function SPL1and2Helper(id1, id2)

