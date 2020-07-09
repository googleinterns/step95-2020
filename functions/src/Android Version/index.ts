import * as functions from 'firebase-functions';
import * as express from 'express';
import * as bodyParser from "body-parser";

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());


export const getAndroidVersion = functions.https.onRequest(main);

app.get('/androidVersions', (request, response) => {
    const androidVersionID = request.query.androidVersion;
    if (androidVersionID !== null){
      //TODO: call helper function to query for android version data
    }

    response.send('Testing android version get.');

});

app.get('/supportedAndroidVersions', (request,response) => {
    //TODO: call function to get all supported android versions

    response.send('Testing supported android versions get');
});

app.get('/androidVersions/:androidVersion/cve', (request,response) => {
    const androidVersionid = request.params.androidVersion;
    if (androidVersionid !== null){
        //TODO: call function to get cve info for given android version
    }
    
    response.send('Testing android version cve get');
});

//function androidVersionCVEHelper(id)
//function supportedAndroidVersionsHelper()
//function androidVersionIDHelper(id)


