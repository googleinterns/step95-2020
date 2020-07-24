
import * as admin from 'firebase-admin';
import * as readInput from './readInput';
import * as config from '../config';


const bulletinJSON = readInput.getConvertedInputFile(); //get parsed JSON
const version = readInput.getVersion(); //get version of bulletin
// Initialize Firebase
admin.initializeApp(config.firebaseConfig);

const rawCVE = getCVEs(bulletinJSON, version.toString()); //create CVE tree

const JSONData = JSON.parse(JSON.stringify(rawCVE)); //CVE JSON data
const longVersionNumber = "BulletinVersion:" + version;

for (const cve in JSONData) {
    const value = JSONData[cve];
    replacePeriodsWithUnderscores(value.version_data);
    //keys are not accepted with periods in realtime db
    replacePeriodsWithUnderscores(value.version_patch_links);
}

if (JSONData) {
    writeToDatabaseCVETree(JSONData, version);
}


function replacePeriodsWithUnderscores(source: any): void {
    if (source) {
        for (const versionDataSub of Object.keys(source)) {
            const versionDataSubChanged = versionDataSub.replace(/\./g, "_");
            source[versionDataSubChanged] = source[versionDataSub];
            delete source[versionDataSub];
        }
    }
}

function getCVEs(data: { vulnerabilities: any; ASB: any; published: any; }, versionNumber: string): Record<string, object> {
    const subCVEData: Record<string, object> = {};
    const regex = /^CVE-\d{4}-\d{3,7}$/;
    for (const vul of data.vulnerabilities) {
        if (vul.CVE === undefined || vul.CVE === null) {
            continue;
        }
        if (!regex.test(vul.CVE)) {
            const hyphenCount = vul.CVE.match(/-/g).length;
            const vulCVEArray = vul.CVE.split("-");
            if (hyphenCount !== 3) { //allow for CVE-___-___-1
                const editedID = checkCVEValidity(vul.CVE, regex); //check if CVE is valid but malformed
                if (editedID.length === 1) { //only one ID 
                    vul.CVE = editedID[0];
                    subCVEData[vul.CVE] = buildSubCVEData(vul, versionNumber, data.published);

                } else {
                    for (const element of editedID) { //multiple IDS (i.e. malformed had two IDS in one)
                        subCVEData[element] = buildSubCVEDataMultiple(vul, versionNumber, data.published, element);
                    }
                }
                continue;
            } else if (vulCVEArray[3].length !== 1) { //check if fits -1 and if not check if valid
                const editedID = checkCVEValidity(vul.CVE, regex);
                if (editedID.length !== 0) {
                    vul.CVE = editedID[0];
                    subCVEData[vul.CVE] = buildSubCVEData(vul, versionNumber, data.published);
                }
                continue;
            }
        }

        subCVEData[vul.CVE] = buildSubCVEData(vul, versionNumber, data.published);
    }
    const result = subCVEData;
    return result;
}

 function checkCVEValidity(ID: string, regExpression: any): any {
    //These are the types of malformations found thus far
    const finalID: any[] = [];
    if (ID.match(/\n/)) { //ex: CVE-2018-9409\n
        const newID = ID.replace('\n', '');
        if (regExpression.test(newID)) {
            finalID.push(newID);
        }
        return finalID;
    }
    if (ID.indexOf(",") !== -1) { //ex: CVE-2015-1094, CVE-2015-1095 
        const idCommaArray = ID.split(",");
        for (let element of idCommaArray) {
            element = element.trim();
            if (regExpression.test(element)) {
                finalID.push(element);
            }
        }
        return finalID;
    }
    if (ID.indexOf("(") !== -1) { //ex: CVE-2017-14879 (Also assigned to A-63890276)
        const indexOfParenthesisFirst = ID.indexOf("(");
        const indexOfParenthesisEnd = ID.indexOf(")");
        const newID = ID.replace(ID.substring(indexOfParenthesisFirst, indexOfParenthesisEnd + 1), "");
        const trimmedID = newID.trim();
        if (regExpression.test(ID)) {
            finalID.push(trimmedID);
        }
        return finalID;
    }
    return finalID;
}

function buildSubCVEData(vulnerability: any, versionNum: any, publishDate: any): any {
    const cveData: Record<string, object> = {};
    cveData['published_date'] = publishDate;
    cveData['BulletinVersion'] = Object(versionNum);
    for (const key of Object.keys(vulnerability)) {
        cveData[key] = vulnerability[key];
    }
    return cveData;
}

function buildSubCVEDataMultiple(vulnerability: any, versionNum: any, publishDate: any, ID: string): any {
    const cveData: Record<string, object> = {};
    cveData['published_date'] = publishDate;
    cveData['BulletinVersion'] = Object(versionNum);
    for (const key of Object.keys(vulnerability)) {
        if (key === "CVE") {
            cveData[key] = Object(ID);
        }
        else {
            cveData[key] = vulnerability[key];
        }
    }
    return cveData;
}


function postCVEHistory(data: any, tree: any, version_number: string): void {
    //get current cve history tree
    const db = admin.database();
    const ref = db.ref('/CVE_History');
    let result = null;
    ref.once('value', function (snapshot) {
        result = snapshot.toJSON();
        buildCVEHistoryTree(result, version_number, tree);
    }).catch(error => { console.log("Error with writing new CVE history tree to db: " + error) });
}


function buildCVEHistoryTree(tree: any, versionHistory: string, cveTree: any): void {
    //key is ASB:Version
    const initalID = Object.keys(JSONData)[0];
    const currentASB = cveTree[initalID]['ASB'];
    const longVersionNumberHistory = currentASB + ":" + versionHistory;
    const db = admin.database();5
    const ref = db.ref('/CVE_History');
    if (tree === null) {
        //if no data present in history tree, send reconfigured cve tree
        for (const ID in cveTree) {
            const tempVersion = cveTree[ID]['BulletinVersion'];
            delete cveTree[ID]['BulletinVersion'];
            const tempLongVersionNumber = cveTree[ID]['ASB'] + ":" + tempVersion;
            ref.child(ID).child(tempLongVersionNumber).set(cveTree[ID]).catch(
                error => { console.log("Error adding all current CVE Tree data into blank history tree:" + error) });
        }
    } else {
        for (const CVE in cveTree) {
            if (!Object.values(cveTree).includes(CVE)) {
                //if CVE not in CVE History tree add data 
                const tempVersion = cveTree[CVE]['BulletinVersion'];
                delete cveTree[CVE]['BulletinVersion'];
                const tempLongVersionNumber = cveTree[CVE]['ASB'] + ":" + tempVersion;
                ref.child(CVE).child(tempLongVersionNumber).set(cveTree[CVE]).catch(error => { console.log("Error adding in CVE into history tree:" + error) });
            }
        }
        for (const CVE in tree) {
            //check if latest version in history tree
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
                    ref.child(CVE).child(longVersionNumberHistory).update(constructedData).catch(error => { console.log("Error adding CVE to history tree:" + error) });
                }
            }
        }
    }
    console.log("CVE History tree built.");
}

function writeToDatabaseCVETree(data: any, versionNum: string): void{
    const db = admin.database();
    const newRef = db.ref('/CVEs');

    let result = null;
    let versionOK = null; 
    const currentTree = newRef.once('value');
    const currentTreeCheck = currentTree.then((snapshot) => {
        result = snapshot.toJSON();
        versionOK = validVersionNumber(versionNum, result);
        const promises = [];
        promises.push(versionOK);
        return Promise.all(promises);

    })

    currentTreeCheck.then((versionCheck) => {
        if (versionCheck[0]) { //if not an older version of bulletin being passed in update data
            for (const ID in data) {
                newRef.child(ID).set(data[ID]).catch(error => { console.log("Error sending CVE tree to database:" + error) });
            }
            pullFromDatabase(longVersionNumber, version.toString());
        }
        console.log("CVE Tree uploaded");
       
    }).catch(error => {console.log("Error checking bulletin version and writing cve tree to db" + error)});
}


function validVersionNumber(versionNum: string, tree: any): boolean {
    //check if bulletin version being sent is older than current version
    const initalID = Object.keys(JSONData)[0];
    if (tree[initalID] === null || tree[initalID] === undefined){
        return true; 
    }
    const currentBulletinVersion = tree[initalID]['BulletinVersion'];
    const tempVersion = versionNum.toString().replace("_", ".");
    const tempCurrentBulletinVersion = currentBulletinVersion.replace("_", ".");
    if (tempVersion < tempCurrentBulletinVersion) {
        return false;
    }
    return true;
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
        buildBulletinVersionTree(result);
    }).catch(error => { console.log("Error fetching CVE Tree from database:" + error) });
}

function buildBulletinSPLTree(tree: any): void {
    clearTreeInDB("Bulletin_SPL");
    const asbSPlMap = new Map<string, Set<any>>();
    for (const cve in tree) {
        const cveData = tree[cve];
        const currentASB = cveData.ASB;
        let currentSPL = cveData.patch_level
        if (currentSPL === undefined || currentSPL === null){
            currentSPL = currentASB + "-01";
        }
        if (currentASB && currentSPL) {
            const previousSet = asbSPlMap.get(currentASB);
            if (previousSet) {
                asbSPlMap.set(currentASB, previousSet.add(currentSPL));
            } else {
                const newSet = new Set();
                newSet.add(currentSPL);
                asbSPlMap.set(currentASB, newSet);
            }
        }
    }
    sendBulletinSPLTreeToDB(asbSPlMap);
}

function clearTreeInDB(treeToClear: string): void {
    const db = admin.database();
    const ref = db.ref('/' + treeToClear);
    ref.remove().catch(error => { console.log("Error clearing tree:" + error) });
}

function sendBulletinSPLTreeToDB(treeToSend: Map<string, Set<any>>): void {
    const db = admin.database();
    const refBulletinSPL = db.ref('/Bulletin_SPL');
    for (const key of treeToSend.keys()) {
        const set = treeToSend.get(key);
        let array = null;
        if (set) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
            refBulletinSPL.child(key).set(array).catch(error => { console.log("Error adding to Bulletin SPL Tree:" + error) });
        }
    }
    console.log("Bulletin SPL uploaded");
}


function buildSPLCVEIDTree(tree: any): void {
    clearTreeInDB("SPL_CVE_IDs");
    const splCVEIDMap = new Map<string, Set<any>>();
    const splPublishDateMap = new Map();
    for (const cve in tree) {
        const cveData = tree[cve];
        let currentSPL = cveData.patch_level;
        if (currentSPL === null || currentSPL === undefined){
            currentSPL = cveData.ASB + "-01";
        }
        splPublishDateMap.set(currentSPL, cveData.published_date);
        if (currentSPL) {
            const previousSet = splCVEIDMap.get(currentSPL);
            if (previousSet) {
                splCVEIDMap.set(currentSPL, previousSet.add(cve));
            } else {
                const newSet = new Set();
                newSet.add(cve);
                splCVEIDMap.set(currentSPL, newSet);
            }
        }
    }
    sendSPLCVEIDTreeToDB(splCVEIDMap, splPublishDateMap);
}

function sendSPLCVEIDTreeToDB(treeToSend: Map<string, Set<any>>, publishMap: any): void {
    const db = admin.database();
    const ref = db.ref('/SPL_CVE_IDs');
    for (const key of treeToSend.keys()) {
        const set = treeToSend.get(key);
        const publishDate = publishMap.get(key);
        let array = null;
        if (set) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
            const addSet: Record<string, object> = {};
            addSet['CVE_IDs'] = array;
            addSet['Published_Date'] = publishDate
            ref.child(key).set(addSet).catch(error => { console.log("Error adding CVE to SPL CVE ID Tree:" + error) });
        }
    }
    console.log("SPl CVE IDs uploaded");
}

function buildAOSPVersionASBCVEIDTree(tree: any): void {
    clearTreeInDB("AOSP_Version_ASB_CVE_IDs");
    const asbCVEIDMap = new Map<string, Set<any>>();
    const aospASBMap = new Map<string, Set<any>>();
    for (const cve in tree) {
        const tempCVEData = tree[cve];
        if (tempCVEData.ASB && cve) {
            const previousMap = asbCVEIDMap.get(tempCVEData.ASB);
            if (previousMap) {
                asbCVEIDMap.set(tempCVEData.ASB, previousMap.add(cve));
            } else {
                const newSet = new Set();
                newSet.add(cve);
                asbCVEIDMap.set(tempCVEData.ASB, newSet);
            }
        }
        if (typeof tempCVEData.aosp_versions !== "undefined") {
            for (const aospNumber in tempCVEData.aosp_versions) {
                const aospVersion = tempCVEData.aosp_versions[aospNumber];
                if (aospVersion && cve && tempCVEData.ASB) {
                    const previousMap = aospASBMap.get(aospVersion);
                    if (previousMap) {
                        aospASBMap.set(aospVersion, previousMap.add(tempCVEData.ASB));
                    } else {
                        const newSet = new Set();
                        newSet.add(tempCVEData.ASB);
                        aospASBMap.set(aospVersion, newSet);
                    }
                }
            }
        }
    }
    sendAOSPVersionASBCVEIDTreeToDB(aospASBMap, asbCVEIDMap, tree);
}

function sendAOSPVersionASBCVEIDTreeToDB(aospASBMapSend: Map<string, Set<any>>, asbCVEIDMapSend: Map<string, Set<any>>, tree: any): void {
    const db = admin.database();
    const ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
    for (const key of aospASBMapSend.keys()) {
        const asbCVEIDSet = aospASBMapSend.get(key);
        if (asbCVEIDSet) {
            for (const currentEntry of asbCVEIDSet) {
                const set = asbCVEIDMapSend.get(currentEntry);
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
                ref.child(tempKey).child(currentEntry).set(array).catch(error => { console.log("Error adding CVE to AOSP Version ASB CVE ID Tree:" + error) });
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
    clearTreeInDB("AOSP_Version_CVE_IDs");
    const aospCVEIDMap = new Map<string, Set<any>>();
    for (const cve in tree) {
        const cveData = tree[cve];
        for (const aospNumber in cveData.aosp_versions) {
            let aospVersion = cveData.aosp_versions[aospNumber];
            aospVersion = aospVersion.replace(/\./g, "_");
            if (cve) {
                const previousSet = aospCVEIDMap.get(aospVersion);
                if (previousSet) {
                    aospCVEIDMap.set(aospVersion, previousSet.add(cve));
                } else {
                    const newSet = new Set();
                    newSet.add(cve);
                    aospCVEIDMap.set(aospVersion, newSet);
                }
            }
        }
    }

    sendAOSPVersionCVEIDTreeToDB(aospCVEIDMap);
}

function sendAOSPVersionCVEIDTreeToDB(treeToSend: Map<string, Set<any>>): void {
    const db = admin.database();
    const ref = db.ref('/AOSP_Version_CVE_IDs');
    for (const key of treeToSend.keys()) {
        const set = treeToSend.get(key);
        let array = null;
        if (set) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
            const CVEs = { 'CVE_IDs': array };
            ref.child(key).set(CVEs).catch(error =>
                console.log("Error failed to add CVE to AOSP Version CVE ID Tree:" + error));
        }
    }
    console.log("AOSP version CVE IDs tree uploaded");
}

function buildBulletinVersionTree(tree: any): void {
    //Bulletin version tree with latest version stored
    //for each bulletin
    const bulletinVersionMap = new Map<string, Array<string>>();
    for (const cve in tree) {
        const cveData = tree[cve];
        const currentASB = cveData.ASB;
        const currentVersion = cveData.BulletinVersion;
        if (currentASB && currentVersion) {
            const arrayToAdd: string[] = [currentVersion, cveData.published_date];
            bulletinVersionMap.set(currentASB, arrayToAdd);
        }
    }
    sendBulletinVersionTreeToDB(bulletinVersionMap);
}

function sendBulletinVersionTreeToDB(treeToSend: Map<string, Array<string>>): void {
    const db = admin.database();
    const ref = db.ref('/Bulletin_Version');
    for (const key of treeToSend.keys()) {
        const addData: Record<string, string> = {};
        const array = treeToSend.get(key);
        if (array) {
            addData['Latest_Version'] = array[0];
            addData['Release_Date'] = array[1];
        }
        addData['Bulletin_ID'] = key;
        ref.child(key).set(addData).catch(error => { console.log("Error sending Bulletin Version Tree to database" + error) });
    }
    console.log("Bulletin Version tree uploaded");
}

