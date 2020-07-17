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
    const bulletinID = String(request.query.bulletinid);
    if (bulletinID !== null){
      bulletinIDHelper(bulletinID,response);
    }
    const SPLID = String(request.query.splid);
    if (SPLID !== null){
      SPLIDHelper(SPLID,response);
    }
    const SPLStart = request.query.splstart;
    if (SPLStart !== null){
      //TODO: call helper function to query for spl start data 
    }
    const CVEID = String(request.query.cveid); 
    if (CVEID !== null){
      CVEIDHelper(CVEID,response);
    }

    const SPL1 = request.query.spl1;
    const SPL2 = request.query.spl2;
    if (SPL1 !== null && SPL2 !== null){
      //TODO: call helper function for data in between spls
    }

    //response.send('Testing CVE get.');

});

function SPLIDHelper(id:any,res:any){
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

function bulletinIDHelper(id:any,res:any){
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

