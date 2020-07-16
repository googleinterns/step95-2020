import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";
import * as admin from 'firebase-admin';

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getSPL = functions.https.onRequest(main);

app.get('/spls', (request, response) => {

    const bulletinID = String(request.query.bulletinid);
    if (bulletinID !== null){
      bulletinIDHelper(bulletinID,response);
      //TODO: call helper function to query for bulletin data 
      // const ref = db.ref('/Bulletin_SPLs');
      // ref.orderByKey().equalTo(bulletinID).once('value', function(snapshot) {
      //   const data = snapshot.val()
      //   //response.send(snapshot.val());
      //   response.send(data[bulletinID].SPLs);
      // }).catch(error => {console.log(error)});
    }

    const androidVersionID = request.query.androidVersion;
    if (androidVersionID !== null){
      //TODO: call helper function to query for android version data
    }

    //response.send(request.query.name);

});

function bulletinIDHelper(id:any,res:any){
  const db = admin.database();
  const ref = db.ref('/Bulletin_SPLs');
  let splData:any;
  ref.orderByKey().equalTo(id).once('value', function(snapshot) {
    splData = snapshot.val();
    let output:any;
    for(const spl of splData[id].SPLs ){
      db.ref('/SPL_CVE_IDs').orderByKey().equalTo(spl).once('value', function(snapshot1) {
        output = snapshot1.val();
      }).catch(error => {console.log(error)});
    }
    //res.send(splData[id].SPLs);
    res.send(output);
  }).catch(error => {console.log(error)});
  //for spl in data check spl_sve tree
}
//function androidVersionHelper(id)


