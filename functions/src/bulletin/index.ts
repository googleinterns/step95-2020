import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());


export const getBulletin = functions.https.onRequest(main);

app.get('/bulletins', (request, response) => {
    const bulletinID = request.query.bulletinid;
    if (bulletinID !== null){
      //TODO: call helper function to query for bulletin data 
    }
    response.send('Testing bulletin get.');

});

//function bulletinIDHelper(id)

