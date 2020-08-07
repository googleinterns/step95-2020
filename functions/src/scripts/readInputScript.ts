//This file reads in the JSON file if inputted from the command line

import * as yargs from 'yargs';

const args = yargs.option('inputPath', { alias: 'i', demand: true, type: 'string' }).argv;

export function getConvertedInputFile(): any {
    const rawBulletin = readInputFile(); //read bulletin json file
    const bulletinJSON = JSON.parse(rawBulletin); //parse file into json
    return bulletinJSON;
}

export function readInputFile(): any {
    const fs = require('fs');
    const rawJSON = fs.readFileSync(args.inputPath);
    return rawJSON;
}

export function getVersion(): any {
    const splitString = args.inputPath.split('-');
    let version: string | number | null = null;
    if (splitString.length === 6) { //assuming format of json file name is <year>-<month>-partner-bulletin-preview<-version>.json
        splitString[5] = splitString[5].replace(".json", "");
        const versionIndex = splitString[5].indexOf('v');
        version = splitString[5].substring(versionIndex+1);
        version = version.replace(/\./g, "_");
    } else {
        version = 1.0; //default to 1 if no version filename 
    }
    return version; 

}
