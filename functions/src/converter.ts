import * as yargs from 'yargs';

//converter part 1

const args = yargs.option('inputPath', {alias: 'i', demand: true, type: 'string'}).option('outputPath',
               {alias: 'o', demand: true, type:'string'}).argv;
const fs = require('fs');
const rawJSON = fs.readFileSync(args.inputPath);
const dataJSON = JSON.parse(rawJSON);
convertToDBSchema(dataJSON);

function convertToDBSchema(data: { vulnerabilities: any; ASB: any; published: any; }) : void {
const SPLsArray : any[] = [];
const found : string[] = [];
 for(const vulnerabilities of data.vulnerabilities){
    const patchLevel = vulnerabilities.patch_level;  
    if (found.indexOf(patchLevel) === -1 && patchLevel !== undefined) {
        found.push(patchLevel);
        SPLsArray.push(patchLevel);
    }
}
const SPLs = {
    'SPLs': SPLsArray
 };

let ASBs = null;
if (data.ASB === undefined){
    const newDate = data.vulnerabilities[0].ASB;
    console.log(newDate);
    ASBs = { [newDate] : SPLs };
}
else {
    ASBs = { [data.ASB] : SPLs };
}

const Bulletin_SPLs = {'ASBs': ASBs};

const publishDate = data.published;
const result : Record<string, object> = {};
for(const spl of SPLsArray){
    const cveIDsArray : string[] = [];
    const splDetails = {
        'Publish_Date': publishDate,
        'CVE_IDs': cveIDsArray
     };
     for(const vulnerabilities of data.vulnerabilities){
        const patchLevel = vulnerabilities.patch_level;
        if(patchLevel === spl){
            const cveID = vulnerabilities.CVE;
            if (cveID !== undefined){
                splDetails.CVE_IDs.push(cveID);
                }
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

fs.writeFileSync(args.outputPath, JSON.stringify(output));
console.log("Completed conversion!");
}

/*To run this script:
 1. Install yargs (npm i yargs, npm install @types/yargs) and ts-node (npm install -g typescript, npm install -g ts-node)
 2. cd into the src folder in step95-2020/functions
 3. Locate the file path for both the input file and where / what file you would like the output to be written to
 4. Run npm run lint and npm run build to be safe
 4. Run the command: ts-node --project ../tsconfig.json converter.ts --inputPath <file path for input file> --outputPath <file path for outputfile>.json
 NOTE: You are in the source folder of step95-2020/functions. If you want to move up a directory, remember to do ../ before the file name (same for output path)
       Also, the input should be the JSON representation of the bulletin data and the output is in JSON format - make sure your output file ends in .json.
 6. If the converter is successful, Completed conversion! should appear in your terminal. 
 */
