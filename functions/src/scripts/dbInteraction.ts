import * as admin from 'firebase-admin';
import * as dataConversion from './dataConvert';
import * as cleanupFunction from './cleanupData';

export async function convert(bulletinData: any, versionInput: any) {
    const rawCVE = dataConversion.getCVEs(bulletinData, versionInput.toString()); //create CVE tree

    const JSONData = JSON.parse(JSON.stringify(rawCVE)); //CVE JSON data
    const longVersionNumber = "BulletinVersion:" + versionInput;

    for (const cve in JSONData) {
        const value = JSONData[cve];
        cleanupFunction.replacePeriodsWithUnderscores(value.version_data);
        //keys are not accepted with periods in realtime db
        cleanupFunction.replacePeriodsWithUnderscores(value.version_patch_links);
    }

    if (JSONData) {
        return writeToDatabaseCVETree(JSONData, versionInput, longVersionNumber);
    }
}

function postCVEHistory(data: any, tree: any, version_number: string): Promise<any> {
    //get current cve history tree
    const db = admin.database();
    const ref = db.ref('/CVE_History');
    let result = null;
    return ref.once('value').then(function (snapshot) {
        result = snapshot.toJSON();
        const builtCVEHistoryTree = dataConversion.buildCVEHistoryTree(result, version_number, tree, data);
        return sendCVEHistoryToDB(builtCVEHistoryTree);
    }).catch(error => { console.log("Error with writing new CVE history tree to db: " + error) });
}

function sendCVEHistoryToDB(treeToSend:any): any {
    //key is ASB:Version
    const db = admin.database();
    const ref = db.ref('/CVE_History');
    const promises: any[] = [];
    if (treeToSend.length === 1){
        const map = treeToSend[0];
        for (const key of map.keys())
        promises.push(ref.child(key).child(map.get(key)[0]).set(map.get(key)[1]).catch(
            error => { console.log("Error adding all current CVE Tree data into blank history tree:" + error) }));
    }
    else {
        const setMap = treeToSend[0];
        const updateMap = treeToSend[1];
        for (const key of setMap.keys()){
            promises.push(ref.child(key).child(setMap.get(key)[0]).set(setMap.get(key)[1]).catch(error => { console.log("Error adding in CVE into history tree:" + error) }));
        }
        for (const key of updateMap.keys()){
            promises.push(ref.child(key).child(updateMap.get(key)[0]).update(updateMap.get(key)[1]).catch(error => { console.log("Error adding CVE to history tree:" + error) }));
        }
    }
    console.log("CVE History tree uploaded");
    return Promise.all(promises);
}

function writeToDatabaseCVETree(data: any, versionNum: string, longNum: any): Promise<any> {
    const db = admin.database();
    const newRef = db.ref('/CVEs');

    let result = null;
    const currentTree = newRef.once('value');
    const currentTreeCheck = currentTree.then((snapshot) => {
        result = snapshot.toJSON();
        const promises = [];
        promises.push(dataConversion.buildCVETree(data, versionNum, result));
        return Promise.all(promises);

    })

    return currentTreeCheck.then(async (versionCheck) => {
        if (versionCheck[0]) { //if not an older version of bulletin being passed in update data
            console.log("writing cve tree to db");
            for (const ID in data) {
                newRef.child(ID).set(data[ID]).catch(error => { console.log("Error sending CVE tree to database:" + error) });
            }
            console.log("CVE Tree uploaded");
            return pullFromDatabase(longNum, versionNum.toString(), data);
        }
        else {
            console.log("Version older than most recent one in db - can't load in data");
        }
    }).catch(error => { console.log("Error checking bulletin version and writing cve tree to db" + error) });
}

function pullFromDatabase(version_full: string, version_short: string, JSONData: any): Promise<any> {
    const db = admin.database();
    const refCVE = db.ref('/CVEs');
    let result = null;
    const promises: any[] = [];
    return refCVE.once('value').then(function (snapshot) {
        result = snapshot.toJSON();
        const bulletinSPLTree = dataConversion.buildBulletinSPLTree(result);
        promises.push(sendBulletinSPLTreeToDB(bulletinSPLTree));
        const splCVEIDTree = dataConversion.buildSPLCVEIDTree(result);
        promises.push(sendSPLCVEIDTreeToDB(splCVEIDTree));
        const aospVersionASBCVEIDTree = dataConversion.buildAOSPVersionASBCVEIDTree(result);
        promises.push(sendAOSPVersionASBCVEIDTreeToDB(aospVersionASBCVEIDTree));
        const aospVersionCVEIDTree = dataConversion.buildAOSPVersionCVEIDTree(result);
        promises.push(sendAOSPVersionCVEIDTreeToDB(aospVersionCVEIDTree));
        promises.push(postCVEHistory(JSONData, result, version_short));
        const bulletinVersionTree = dataConversion.buildBulletinVersionTree(result);
        promises.push(sendBulletinVersionTreeToDB(bulletinVersionTree));
        return Promise.all(promises);
    }).catch(error => { console.log("Error fetching CVE Tree from database:" + error) });
}

function clearTreeInDB(treeToClear: string): void {
    const db = admin.database();
    const ref = db.ref('/' + treeToClear);
    ref.remove().catch(error => { console.log("Error clearing tree:" + error) });
}

function sendBulletinSPLTreeToDB(treeToSend: Map<string, Array<any>>): any {
    clearTreeInDB("Bulletin_SPL");
    const db = admin.database();
    const refBulletinSPL = db.ref('/Bulletin_SPL');
    console.log("writing bulletin spl tree to db");
    const promises: any[] = [];
    for (const key of treeToSend.keys()){
        promises.push(refBulletinSPL.child(key).set(treeToSend.get(key)).catch(error => { console.log("Error adding to Bulletin SPL Tree:" + error) }));
    }
    console.log("Bulletin SPL uploaded");
    return Promise.all(promises);
}

function sendSPLCVEIDTreeToDB(treeToSend: Map<any, any>): any {
    clearTreeInDB("SPL_CVE_IDs");
    console.log("writing spl tree to db");
    const db = admin.database();
    const ref = db.ref('/SPL_CVE_IDs');
    const promises: any[] = [];
    for (const key of treeToSend.keys()){
        promises.push(ref.child(key).set(treeToSend.get(key)).catch(error => { console.log("Error adding CVE to SPL CVE ID Tree:" + error) }));
    }
    console.log("SPl CVE IDs uploaded");
    return Promise.all(promises);
}

function sendAOSPVersionASBCVEIDTreeToDB(treeToSend: any): any {
    clearTreeInDB("AOSP_Version_ASB_CVE_IDs");
    console.log("writing aosp version asb cve tree to db");
    const db = admin.database();
    const ref = db.ref('/AOSP_Version_ASB_CVE_IDs');
    const promises: any[] = [];
    for (const key of treeToSend.keys()){
        promises.push(ref.child(key).child(treeToSend.get(key)[0]).set(treeToSend.get(key)[1]).catch(error => { console.log("Error adding CVE to AOSP Version ASB CVE ID Tree:" + error) }));
    }
    console.log("AOSP version ASB CVE ID tree uploaded");
    return Promise.all(promises);

}

function sendAOSPVersionCVEIDTreeToDB(treeToSend: Map<string, Set<any>>): any {
    clearTreeInDB("AOSP_Version_CVE_IDs");
    console.log("writing aosp version cve id tree to db");
    const db = admin.database();
    const ref = db.ref('/AOSP_Version_CVE_IDs');
    const promises: any[] = [];
    for (const key of treeToSend.keys()){
        promises.push(ref.child(key).set(treeToSend.get(key)).catch(error =>
            console.log("Error failed to add CVE to AOSP Version CVE ID Tree:" + error)));
    }
    console.log("AOSP version CVE IDs tree uploaded");
    return Promise.all(promises);
}

function sendBulletinVersionTreeToDB(treeToSend: Map<any, any>): any {
    console.log("writing bulletin version tree to db");
    const db = admin.database();
    const ref = db.ref('/Bulletin_Version');
    const promises: any[] = [];
    for (const key of treeToSend.keys()){
        promises.push(ref.child(key).set(treeToSend.get(key)).catch(error => { console.log("Error sending Bulletin Version Tree to database" + error) }));
    }
    console.log("Bulletin Version tree uploaded");
    return Promise.all(promises);
}
