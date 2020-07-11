import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getSPL = functions.https.onRequest(main);

app.get('/spls', (request, response) => {
    const bulletinID = request.query.bulletinid;
    if (bulletinID !== null){
      //TODO: call helper function to query for bulletin data 
    }
    const androidVersionID = request.query.androidVersion;
    if (androidVersionID !== null){
      //TODO: call helper function to query for android version data
    }

    response.send('Testing SPL get.');

});

//function bulletinIDHelper(id)
//function androidVersionHelper(id)


