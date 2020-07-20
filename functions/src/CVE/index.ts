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
    if (bulletinID !== null){
      //TODO: call helper function to query for bulletin data 
    }
    const SPLID = request.query.splid;
    if (SPLID !== null){
      //TODO: call helper function to query for spl data
    }
    const SPLStart = String(request.query.splstart);
    if (SPLStart !== null){
      splStartHelper(SPLStart, response); 
    }
    const CVEID = request.query.cveid; 
    if (CVEID !== null){
      //TODO: call helper function for cve id data 
    }
    const SPL1 = request.query.spl1;
    const SPL2 = request.query.spl2;
    if (SPL1 !== null && SPL2 !== null){
      //TODO: call helper function for data in between spls
      // SPL1and2Helper(SPL1, SPL2, response);
    }
    console.log('Testing CVE...');}
);

//function bulletinIDHelper(id)
//function SPLIDHelper(id)
//function SPLStartHelper(id)
//function CVEIDHelper(id)
//function SPL1and2Helper(id1, id2)

function splStartHelper(id : string, res : any) : void {
  var db = admin.database();
  var ref = db.ref('/CVEs');

  ref.on("value", function(snapshot) {
    let cves = snapshot.val();
    let cve_array : Array<any> = [];
    
    const cve_jsons : any = Enumerable.from(cves)
      .where(function(obj) {return obj.value['ASB'] < id})
      .select(function (obj){
        return obj.value;
      })

    for (const cve of cve_jsons){
      cve_array.push(cve);
    }

  const result = {
    'CVEs' : cve_array
  }
  res.send(result);
  }, function(error) { console.log(error);});
  }
