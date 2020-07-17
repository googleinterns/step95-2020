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
  console.log("db initd!")
  const ref = db.ref('/Bulletin_SPLs');
  let splData:any;
  //const id = "2018-04";
  const bulletinToSplPromise = ref.orderByKey().equalTo(id).once('value');
  const allSplPromise = bulletinToSplPromise.then((snapshot) => {
      splData = snapshot.val();
      let promises:Array<any> = [];
      for(const spl of splData[id].SPLs ){
          console.log(spl);
          const splPromise = db.ref('/SPL_CVE_IDs').orderByKey().equalTo(spl).once('value');
          promises.push(splPromise);
      }
      return Promise.all(promises) ;
  })
  .catch(error => {console.log("error getting spls for bulletin id: " + error)});

  allSplPromise.then((result: Array<any> | void) => {
      // return API response to user here
      if (result !== undefined){
        // for (const x of result) {
        //   console.log(x.val());
        // }
        res.send(result);
      }
  });
  // const db = admin.database();
  // const ref = db.ref('/Bulletin_SPLs');
  // let splData:any;
  // ref.orderByKey().equalTo(id).once('value', function(snapshot) {
  //   splData = snapshot.val();
  //   console.log("splData"+splData);
  //   console.log("array"+splData[id].SPLs);
  //   let output:any;
  //   for(const spl of splData[id].SPLs ){
  //     db.ref('/SPL_CVE_IDs').orderByKey().equalTo(spl).once('value', function(snapshot1) {
  //       output = snapshot1.val();
  //       console.log("output"+output);
  //     }).catch(error => {console.log(error)});
  //   }
  //   //res.send(splData[id].SPLs);
  //   res.send(output);
  // }).catch(error => {console.log(error)});
  // //for spl in data check spl_sve tree
}
//function androidVersionHelper(id)


