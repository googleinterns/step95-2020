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

//function bulletinIDHelper(id)
function bulletinIDHelper(id:any,res:any){
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.once('value', function(snapshot) {
    let cves = snapshot.val();
    cves = Enumerable.from(cves)
    .where(function (obj) { return obj.value["BulletinVersion:1"].ASB === id })
    .select(function (obj) { return obj.value })
    .toArray()
    res.send(cves);
  }).catch(error => {console.log(error)});
}

//mock data for "cves"
// const object = {
//   "CVE-2015-9016": {
//    "BulletinVersion:1": {
//     "ASB": "2018-02",
//     "CVE": "CVE-2015-9016",
//     "android_id": "A-63083046",
//     "area": "Kernel",
//     "component": "Kernel components",
//     "fix_details": "The fix is designed to properly track active multi-queue block IO requests and simplify blk_mq_tag_to_rq.",
//     "patch_level": "2018-02-05",
//     "patch_links": ["https://github.com/torvalds/linux/commit/0048b4837affd153897ed1222283492070027aa9"],
//     "published_date": "2018-01-01",
//     "severity": "High",
//     "subcomponent": "Multi-queue block IO",
//     "tech_details": "In blk_mq_tag_to_rq in blk-mq.c, there is a possible use after free due to a race condition when a request has been previously freed by blk_mq_complete_request. This could lead to local escalation of privilege.",
//     "type": "EoP",
//     "vendor": "Upstream Linux"
//    }
//   },
//   "CVE-2016-10393": {
//    "BulletinVersion:1": {
//     "ASB": "2018-03",
//     "CVE": "CVE-2016-10393",
//     "android_id": "A-68326806",
//     "area": "Kernel",
//     "component": "Qualcomm closed-source components",
//     "fix_details": "",
//     "notes": "Qualcomm AMSS bulletin: December 2016",
//     "patch_level": "2018-03-05",
//     "published_date": "2018-02-01",
//     "references": ["QC-CR#1055934"],
//     "severity": "High",
//     "subcomponent": "Video",
//     "tech_details": "",
//     "vendor": "Qualcomm"
//    }
//   },
//   "CVE-2016-10394": {
//    "BulletinVersion:1": {
//     "ASB": "2018-03",
//     "CVE": "CVE-2016-10394",
//     "android_id": "A-68326803",
//     "area": "Kernel",
//     "component": "Qualcomm closed-source components",
//     "fix_details": "",
//     "notes": "Qualcomm AMSS bulletin: December 2016",
//     "patch_level": "2018-04-05",
//     "published_date": "2018-02-01",
//     "references": ["QC-CR#1043068"],
//     "severity": "Critical",
//     "subcomponent": "Secure systems group",
//     "tech_details": "",
//     "vendor": "Qualcomm"
//    }
//   }
// };

// //select cves that have "ASB": "2018-03"
// const idd = '2018-02';
// //Enumerable.from(object).forEach(function(obj) { console.log(obj.value["BulletinVersion:1"].ASB) });
// const test = Enumerable.from(object)
// .where(function (obj) { return obj.value["BulletinVersion:1"].ASB === idd })
// .select(function (obj) { return obj.value })
// .toArray()
// console.log(test);

function SPLIDHelper(id:any,res:any){
  const db = admin.database();
  const ref = db.ref('/CVEs');
  ref.once('value', function(snapshot) {
    let cves = snapshot.val();
    cves = Enumerable.from(cves)
    .where(function (obj) { return obj.value["BulletinVersion:1"].patch_level === id })
    .select(function (obj) { return obj.value })
    .toArray()
    res.send(cves);
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

