import * as yargs from 'yargs';
const args = yargs.option('inputPath', { alias: 'i', demand: true, type: 'string' }).argv;

export function readInputFile(): any {
    const fs = require('fs');
    const rawJSON = fs.readFileSync(args.inputPath);
    return rawJSON;
}

export function getVersion(): any {
    const splitString = args.inputPath.split('-');
    let version: string | number | null = null;
    let versionArray = null;
    if (splitString.length === 6) { //assuming format of json file name is <year>-<month>-partner-bulletin-preview<-version>.json
        versionArray = splitString[5].split('.')[0].split('v');
        version = versionArray[1];
    } else {
        version = 1.0;
    }
    return version; 

}
