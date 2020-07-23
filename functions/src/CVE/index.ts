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
  getUserToken(request, response, true);
 })
  
function getUserToken(request : any, response : any, useToken : boolean) {
if (useToken){
  if (!request.headers['token']) {
    response.send('Token required for API usage!');
  } else {
    const userToken : string = request.headers['token'];
    decodeUserIdToken(userToken, request, response);
  }
}
else{
  getCVE_functions('bypass', request, response);
}
}

function decodeUserIdToken(userToken : string, request : any, response : any) {
let userDecodedToken : any = null;
admin.auth().verifyIdToken(userToken).then(function (decodedToken) {
  userDecodedToken = decodedToken;
  getCVE_functions(userDecodedToken.uid, request, response)
}).catch(function (error) {
  console.log(error);
});
}

function getCVE_functions(uid : string, request : any, response : any){
  const bulletinID = request.query.bulletinid;
  const splID = request.query.splid;
  const splStart = request.query.splstart;
  const cveID = request.query.cveid;
  const spl1 = request.query.spl1;
  const spl2 = request.query.spl2;  

  if (bulletinID){
    getCvesWithBulletinID(String(bulletinID),response);
  }
  else if (splID){
    getCvesWithSplID(String(splID),response);
  }
  else if (splStart){
    if (splStart !== null && (uid == 'c32xG9Qb0ddlBHj8LGF3414gWxn1')){
      splStartHelper(String(splStart), response);
    }
    else { response.send('Use does not have access');
    }
  } 
  else if (cveID){
    getCveWithCveID(String(cveID),response);
  }
  else if (spl1 && spl2){
    //TODO: call helper function for data in between spls
    // SPL1and2Helper(SPL1, SPL2, response);
  }
}

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
    res.send("error getting CVEs for bulletinID:"+ error);
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
    res.send("error getting CVEs for spl:"+ error);
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
    res.send("error getting details for CVEID:"+ error);
  });
}

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