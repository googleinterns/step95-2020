//This file reads in the JSON file if inputted from the UI

export function getConvertedInputFile(filePath: string): any {
    const rawBulletin = readInputFile(filePath); //read bulletin json file
    const bulletinJSON = JSON.parse(rawBulletin); //parse file into json
    return bulletinJSON;
}

export function readInputFile(filePath: string): any {
     const fs = require('fs');
     const rawJSON = fs.readFileSync(filePath);
     return rawJSON; 
}

export function getVersion(filepath: any): any {
   const string = filepath.substring(15);
   const splitString = string.split('-');
    let version = null;
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
