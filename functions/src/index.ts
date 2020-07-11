import * as admin from 'firebase-admin';
import * as express from 'express';
import * as bodyParser from "body-parser";

 const firebaseConfig = {
  apiKey: "AIzaSyBfQKMxa1azXidOZJjT8UYDm5BnU4s2bKA", 
  authDomain: "step95-2020.firebaseapp.com", 
  databaseURL: "https://step95-2020.firebaseio.com", 
  projectId: "step95-2020", 
  storageBucket: "step95-2020.appspot.com", 
  messagingSenderId: "525367632678", 
  appId: "1:525367632678:web:476053e80e5f22c6f417e7", 
  measurementId: "G-QJE1CBXKGN"
  };
  // Initialize Firebase
admin.initializeApp(firebaseConfig);

import * as CVEFunction from './CVE/index';
import * as SPLFunction from './SPL/index';
import * as bulletinFunction from './bulletin/index';
import * as androidVersionFunction from './Android Version/index';

const app = express();
const main = express();

main.use(app);
main.use(bodyParser.json());

export const getCVEFunction = CVEFunction.getCVE;
export const getSPLFunction = SPLFunction.getSPL;
export const getBulletinFunction = bulletinFunction.getBulletin;
export const getAndroidVersionFunction = androidVersionFunction.getAndroidVersion;

//converter
import * as data from './bulletin.json';

const SPLsArray : any[] = [];
const found : string[] = [];
 for(const vulnerabilities of data.vulnerabilities){
    const patchLevel = vulnerabilities.patch_level;  
    if (found.indexOf(patchLevel) === -1) {
        found.push(patchLevel);
        SPLsArray.push(patchLevel);
    }
}
const SPLs = {
    'SPLs': SPLsArray
 };
const ASBs = { [data.ASB] : SPLs };
const Bulletin_SPLs = {'ASBs': ASBs};

const pubishDate = data.published;
const result : Record<string, object> = {};
for(const spl of SPLsArray){
    const cveIDsArray : string[] = [];
    const splDetails = {
        'Publish_Date': pubishDate,
        'CVE_IDs': cveIDsArray
     };
     for(const vulnerabilities of data.vulnerabilities){
        const patchLevel = vulnerabilities.patch_level;
        if(patchLevel === spl){
            const cveID = vulnerabilities.CVE;
            splDetails.CVE_IDs.push(cveID);
        }
        result[spl] = splDetails;
      }
}

const SPL_CVE_IDs = {'SPLs' : result};
const output = {SPL_CVE_IDs, Bulletin_SPLs};

//TODO
// const AOSP_VERSION_CVE_IDs 
// const AOSP_VERSION_ASB_CVE_IDs 
// const CVEs 

const fs = require('fs');
fs.writeFileSync('../convertedData.json', JSON.stringify(output));