
import * as admin from 'firebase-admin';
import * as readInput from './readInput';


const rawBulletin = readInput.readInputFile(); //read bulletin json file
const bulletinJSON = JSON.parse(rawBulletin); //parse file into json 
const version = readInput.getVersion(); //get version of bulletin
//if no version in file name default to 1

const firebaseConfig = {
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

const rawCVE = getCVEs(bulletinJSON, version.toString()); //create CVE tree

const JSONData = JSON.parse(JSON.stringify(rawCVE)); //CVE JSON data
const longVersionNumber = "BulletinVersion:" + version;

for (const CVE in JSONData) {
    const value = JSONData[CVE];
    replacePeriodsWithUnderscores(value.version_data);
    //keys are not accepted with periods in realtime db
    replacePeriodsWithUnderscores(value.version_patch_links);
}

writeToDatabaseCVETree(JSONData); //update CVE Tree

pullFromDatabase(longVersionNumber, version.toString()); //pull whole CVE tree

function replacePeriodsWithUnderscores(source: any): void {
    if (source !== null && source !== undefined) {
        for (const versionDataSub of Object.keys(source)) {
            const versionDataSubChanged = versionDataSub.replace(/\./g, "_");
            source[versionDataSubChanged] = source[versionDataSub];
            delete source[versionDataSub];
        }
    }
}

function getCVEs(data: { vulnerabilities: any; ASB: any; published: any; }, versionNumber: string): Record<string, object> {
    const subCVEData: Record<string, object> = {};
    for (const vul of data.vulnerabilities) {
        const cveData: Record<string, object> = {};
        cveData['published_date'] = data.published;
        cveData['BulletinVersion'] = Object(versionNumber);
        for (const key of Object.keys(vul)) {
            cveData[key] = vul[key];
        }
        subCVEData[vul.CVE] = cveData;
    }
    const result = subCVEData;
    return result;
}

function postCVEHistory(data: any, tree: any, version_number: string): void {
    //get current cve history tree
    const db = admin.database();
    const ref = db.ref('/CVE_History');
    let result = null;
    ref.once('value', function (snapshot) {
        result = snapshot.toJSON();
        buildCVEHistoryTree(result, version_number, tree);
    }).catch(error => { console.log(error) });
}


function buildCVEHistoryTree(tree: any, versionHistory: string, CVETree: any): void {
    //add new version sub section to cve history if needed 
    const longVersionNumberHistory = "BulletinVersion:" + versionHistory;
    const db = admin.database();
    const ref = db.ref('/CVE_History');
    if (tree === null) {
        //if no data present in history tree, send whole reconfigured cve tree
        for (const ID in CVETree) {
            const tempVersion = CVETree[ID]['BulletinVersion'];
            delete CVETree[ID]['BulletinVersion'];
            const tempLongVersionNumber = "BulletinVersion:" + tempVersion;
            ref.child(ID).child(tempLongVersionNumber).set(CVETree[ID]).catch(error => { console.log(error) });
        }
    } else {
        for (const CVE in CVETree) {
            if (!Object.values(CVETree).includes(CVE)) {
                const tempVersion = CVETree[CVE]['BulletinVersion'];
                delete CVETree[CVE]['BulletinVersion'];
                const tempLongVersionNumber = "BulletinVersion:" + tempVersion;
                ref.child(CVE).child(tempLongVersionNumber).set(CVETree[CVE]).catch(error => { console.log(error) });
            }
        }
        for (const CVE in tree) {
            //check if version in history tree
            const currentTreeCVEData = tree[CVE];
            let hasKey = false;
            if (JSONData[CVE] !== undefined) {
                for (const key of Object.keys(currentTreeCVEData)) {
                    if (key === longVersionNumberHistory) {
                        hasKey = true;
                    }
                }
                if (!hasKey) {
                    //if doesn't have version add in the data
                    const cveData: Record<string, object> = {};
                    cveData['published_date'] = JSONData.published;
                    for (const key of Object.keys(JSONData[CVE])) {
                        cveData[key] = JSONData[CVE][key];
                    }
                    const constructedData = JSON.parse(JSON.stringify(cveData));
                    delete constructedData['BulletinVersion'];
                    ref.child(CVE).child(longVersionNumberHistory).update(constructedData).catch(error => { console.log(error) });
                }
            }
        }
    }
    console.log("CVE History tree built");
}

function writeToDatabaseCVETree(data: any): void {
    const db = admin.database();
    const newRef = db.ref('/CVEs');
    for (const ID in data) {
        newRef.child(ID).set(data[ID]).catch(error => { console.log(error) });
    }
    console.log("CVE tree uploaded");
}

function pullFromDatabase(version_full: string, version_short: string): void {
    const db = admin.database();
    const refCVE = db.ref('/CVEs');
    let result = null;
    refCVE.once('value', function (snapshot) {
        result = snapshot.toJSON();
        buildBulletinSPLTree(result);
        buildSPLCVEIDTree(result);
        buildAOSPVersionASBCVEIDTree(result);
        buildAOSPVersionCVEIDTree(result);
        postCVEHistory(JSONData, result, version_short);
    }).catch(error => { console.log(error) });
}

function buildBulletinSPLTree(tree: any): void {
    const db = admin.database();
    let refBulletinSPL = db.ref('/Bulletin_SPLs');
    refBulletinSPL.remove().catch(error => { console.log(error) });
    const ASBSPlMap = new Map<string, Set<any>>();
    for (const CVE in tree) {
        const CVEData = tree[CVE];
        const currentASB = CVEData.ASB;
        const currentSPL = CVEData.patch_level
        if (currentASB !== undefined && currentSPL !== undefined) {
            const previousSet = ASBSPlMap.get(currentASB);
            if (previousSet !== undefined) {
                ASBSPlMap.set(currentASB, previousSet.add(currentSPL));
            } else {
                const newSet = new Set();
                newSet.add(currentSPL);
                ASBSPlMap.set(currentASB, newSet);
            }
        }
    }
    refBulletinSPL = db.ref('/Bulletin_SPL');
    for (const key of ASBSPlMap.keys()) {
        const set = ASBSPlMap.get(key);
        let array = null;
        if (set !== undefined) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
            refBulletinSPL.child(key).set(array).catch(error => { console.log(error) });
        }
    }
    console.log("Bulletin SPL uploaded");

}

function buildSPLCVEIDTree(tree: any): void {
    const db = admin.database();
    let refSPLCVEID = db.ref('/SPL_CVE_IDs');
    refSPLCVEID.remove().catch(error => { console.log(error) });
    const SPLCVEIDMap = new Map<string, Set<any>>();
    for (const CVE in tree) {
        const CVEData = tree[CVE];
        const currentSPL = CVEData.patch_level;
        if (currentSPL !== undefined) {
            const previousSet = SPLCVEIDMap.get(currentSPL);
            if (previousSet !== undefined) {
                SPLCVEIDMap.set(currentSPL, previousSet.add(CVE));
            } else {
                const newSet = new Set();
                newSet.add(CVE);
                SPLCVEIDMap.set(currentSPL, newSet);
            }
        }
    }
    refSPLCVEID = db.ref('/SPL_CVE_IDs');
    for (const key of SPLCVEIDMap.keys()) {
        const set = SPLCVEIDMap.get(key);
        let array = null;
        if (set !== undefined) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
            refSPLCVEID.child(key).set(array).catch(error => { console.log(error) });
        }
    }
    console.log("SPl CVE IDs uploaded");

}

function buildAOSPVersionASBCVEIDTree(tree: any): void {
    const ASBCVEIDMap = new Map<string, Set<any>>();
    const AOSPASBMap = new Map<string, Set<any>>();
    const db = admin.database();
    let ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
    ref.remove().catch(error => { console.log(error) });
    for (const CVE in tree) {
        const tempCVEData = tree[CVE];
        if (tempCVEData.ASB !== undefined && CVE !== undefined) {
            const previousMap = ASBCVEIDMap.get(tempCVEData.ASB);
            if (previousMap !== undefined) {
                ASBCVEIDMap.set(tempCVEData.ASB, previousMap.add(CVE));
            } else {
                const newSet = new Set();
                newSet.add(CVE);
                ASBCVEIDMap.set(tempCVEData.ASB, newSet);
            }
        }
        if (typeof tempCVEData.aosp_versions !== "undefined") {
            for (const aospNumber in tempCVEData.aosp_versions) {
                const aospVersion = tempCVEData.aosp_versions[aospNumber];
                if (aospVersion !== undefined && CVE !== undefined && tempCVEData.ASB !== undefined) {
                    const previousMap = AOSPASBMap.get(aospVersion);
                    if (previousMap !== undefined) {
                        AOSPASBMap.set(aospVersion, previousMap.add(tempCVEData.ASB));
                    } else {
                        const newSet = new Set();
                        newSet.add(tempCVEData.ASB);
                        AOSPASBMap.set(aospVersion, newSet);
                    }
                }
            }
        }
    }
    ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
    for (const key of AOSPASBMap.keys()) {
        const ASBCVEIDSet = AOSPASBMap.get(key);
        if (ASBCVEIDSet !== undefined) {
            for (const currentEntry of ASBCVEIDSet) {
                const set = ASBCVEIDMap.get(currentEntry);
                let array = null;
                if (set !== undefined) {
                    const iterator = set[Symbol.iterator]();
                    array = Array.from(iterator);
                    for (let i = 0; i < array.length; i++) {
                        if (!isAndroidVersionSupported(tree, key, array[i])) {
                            array.splice(i, 1);
                            i--;
                        }
                    }
                    JSON.parse(JSON.stringify(array));
                }
                const tempKey = key.replace(/\./g, "_");
                ref.child(tempKey).child(currentEntry).set(array).catch(error => { console.log(error) });
            }
        }
    }
    console.log("AOSP version ASB CVE ID tree uploaded");
}

function isAndroidVersionSupported(tree: any, aospVersion: string, ID: string): boolean {
    const data = tree[ID];
    if (data.aosp_versions !== undefined) {
        if (Object.values(data.aosp_versions).indexOf(aospVersion) !== -1) {
            return true;
        }
    }
    return false;
}

function buildAOSPVersionCVEIDTree(tree: any): void {
    const db = admin.database();
    let ref = db.ref('/AOSP_Version_CVE_IDs');
    ref.remove().catch(error => { console.log(error) });
    const AOSPCVEIDMap = new Map<string, Set<any>>();
    for (const CVE in tree) {
        const CVEData = tree[CVE];
        for (const aospNumber in CVEData.aosp_versions) {
            let aospVersion = CVEData.aosp_versions[aospNumber];
            aospVersion = aospVersion.replace(/\./g, "_");
            if (CVE !== undefined) {
                const previousSet = AOSPCVEIDMap.get(aospVersion);
                if (previousSet !== undefined) {
                    AOSPCVEIDMap.set(aospVersion, previousSet.add(CVE));
                } else {
                    const newSet = new Set();
                    newSet.add(CVE);
                    AOSPCVEIDMap.set(aospVersion, newSet);
                }
            }
        }
    }
    ref = db.ref('/AOSP_Version_CVE_IDs');
    for (const key of AOSPCVEIDMap.keys()) {
        const set = AOSPCVEIDMap.get(key);
        let array = null;
        if (set !== undefined) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
            const CVEs = { 'CVE_IDs': array };
            ref.child(key).set(CVEs).catch(error => console.log(error));
        }
    }

    console.log("AOSP version CVE IDs tree uploaded");

}


// /*To run this script:
//  1. Install yargs (npm i yargs, npm install @types/yargs) and ts-node (npm install -g typescript, npm install -g ts-node)
//  2. cd into the src folder in step95-2020/functions
//  3. Locate the file path for both the input file and where / what file you would like the output to be written to
//  4. Run npm run lint and npm run build to be safe
//  4. Run the command: ts-node --project ../tsconfig.json converter.ts --inputPath <file path for input file> --outputPath <file path for outputfile>.json
//  NOTE: You are in the source folder of step95-2020/functions. If you want to move up a directory, remember to do ../ before the file name (same for output path)
//        Also, the input should be the JSON representation of the bulletin data and the output is in JSON format - make sure your output file ends in .json.
//  6. If the converter is successful, Completed conversion! should appear in your terminal.
//  */


