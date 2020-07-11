import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";

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
    const SPLStart = request.query.splstart;
    if (SPLStart !== null){
      //TODO: call helper function to query for spl start data 
    }
    const CVEID = request.query.cveid; 
    if (CVEID !== null){
      //TODO: call helper function for cve id data 
    }
    const SPL1 = request.query.spl1;
    const SPL2 = request.query.spl2;
    if (SPL1 !== null && SPL2 !== null){
      //TODO: call helper function for data in between spls
    }

    response.send('Testing CVE get.');

});

//function bulletinIDHelper(id)
//function SPLIDHelper(id)
//function SPLStartHelper(id)
//function CVEIDHelper(id)
//function SPL1and2Helper(id1, id2)

