//This file converts all data from JSON file into desired format for each tree

import * as validCheck from './validData';

export function getCVEs(data: { vulnerabilities: any; ASB: any; published: any; }, versionNumber: string): Record<string, object> {
    const subCVEData: Record<string, object> = {};
    const regex = /^CVE-\d{4}-\d{3,7}$/;
    for (const vul of data.vulnerabilities) {
        if (vul.CVE === undefined || vul.CVE === null) {
            continue;
        }
        if (!regex.test(vul.CVE)) {
            const editedID = validCheck.checkCVEValidity(vul.CVE, regex); //check if CVE is valid but malformed
            if (editedID.length === 1) { //only one ID in ID slot
                vul.CVE = editedID[0];
                subCVEData[vul.CVE] = buildSubCVEData(vul, versionNumber, data.published);

            } else {
                for (const element of editedID) { //multiple IDS (i.e. malformed had two IDS in one)
                    subCVEData[element] = buildSubCVEDataMultiple(vul, versionNumber, data.published, element);
                }
            }
            continue;
        }

        subCVEData[vul.CVE] = buildSubCVEData(vul, versionNumber, data.published);
    }
    const result = subCVEData;
    return result;
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
    //if there aare two ids in one slot
    const cveData: Record<string, object> = {};
    cveData['published_date'] = publishDate;
    cveData['BulletinVersion'] = Object(versionNum);
    for (const key of Object.keys(vulnerability)) {
        if (key === "CVE") {
            cveData[key] = Object(ID);
        } else {
            cveData[key] = vulnerability[key];
        }
    }
    return cveData;
}

export function buildCVEHistoryTree(tree: any, versionHistory: string, cveTree: any, jsonData: any): any {
    //key is ASB:Version
    const initalID = Object.keys(jsonData)[0];
    const currentASB = cveTree[initalID]['ASB'];
    const longVersionNumberHistory = currentASB + ":" + versionHistory;
    let returnArray : any; 
    if (tree === null) {
        const returnMap = new Map();
        //if no data present in history tree, send reconfigured cve tree
        for (const id in cveTree) {
            const tempVersion = cveTree[id]['BulletinVersion'];
            delete cveTree[id]['BulletinVersion'];
            const tempLongVersionNumber = cveTree[id]['ASB'] + ":" + tempVersion;
            const tempArray = [tempLongVersionNumber, cveTree[id]];
            returnMap.set(id, tempArray);
        }
        returnArray = [returnMap];
        return returnArray; 
    } else {
        const setMap = new Map();
        const updateMap = new Map();
        for (const cve in cveTree) {
            if (!Object.values(cveTree).includes(cve)) {
                //if CVE not in CVE History tree add data 
                const tempVersion = cveTree[cve]['BulletinVersion'];
                delete cveTree[cve]['BulletinVersion'];
                const tempLongVersionNumber = cveTree[cve]['ASB'] + ":" + tempVersion;
                const tempArray = [tempLongVersionNumber, cveTree[cve]];
                setMap.set(cve, tempArray);
            }
        }
        for (const cve in tree) {
            //check if latest version in history tree
            const currentTreeCVEData = tree[cve];
            let hasKey = false;
            if (jsonData[cve] !== undefined) {
                for (const key of Object.keys(currentTreeCVEData)) {
                    if (key === longVersionNumberHistory) {
                        hasKey = true;
                    }
                }
                if (!hasKey) {
                    //if doesn't have version add in the data
                    const cveData: Record<string, object> = {};
                    cveData['published_date'] = jsonData.published;
                    for (const key of Object.keys(jsonData[cve])) {
                        cveData[key] = jsonData[cve][key];
                    }
                    const constructedData = JSON.parse(JSON.stringify(cveData));
                    delete constructedData['BulletinVersion'];
                    const tempArray = [longVersionNumberHistory, constructedData];
                    updateMap.set(cve, tempArray);
                }
            }
        }
        returnArray = [setMap, updateMap];
    }
    console.log("CVE History tree built.");
    return returnArray;
}

export function buildCVETree(data: any, versionNum:string, result:any): boolean {
    let versionOK = null; 
    if (result === null){
        versionOK = true; 
    } else {
        versionOK = validCheck.validVersionNumber(versionNum, result, data);
    }
    return versionOK; 
}

export function buildBulletinSPLTree(tree: any): Map<string, Array<any>> {
    const asbSPlMap = new Map<string, Set<any>>();
    for (const cve in tree) {
        const cveData = tree[cve];
        const currentASB = cveData.ASB;
        let currentSPL = cveData.patch_level
        if (currentSPL === undefined || currentSPL === null) {
            //missing patch level
            currentSPL = currentASB + "-01";
        }
        if (currentASB && currentSPL) {
            const previousSet = asbSPlMap.get(currentASB);
            if (previousSet) { //already has a mapping
                asbSPlMap.set(currentASB, previousSet.add(currentSPL));
            } else {
                const newSet = new Set();
                newSet.add(currentSPL);
                asbSPlMap.set(currentASB, newSet);
            }
        }
    }
    const returnMap = new Map();
    for (const key of asbSPlMap.keys()) {
        const set = asbSPlMap.get(key);
        let array = null;
        if (set) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
        }
        returnMap.set(key, array);
    }
    return returnMap; 
}

export function buildSPLCVEIDTree(tree: any): Map<any, any> {
    const splCVEIDMap = new Map<string, Set<any>>();
    const splPublishDateMap = new Map();
    for (const cve in tree) {
        const cveData = tree[cve];
        let currentSPL = cveData.patch_level;
        if (currentSPL === null || currentSPL === undefined) {
            //missing patch level
            currentSPL = cveData.ASB + "-01";
        }
        splPublishDateMap.set(currentSPL, cveData.published_date);
        if (currentSPL) {
            const previousSet = splCVEIDMap.get(currentSPL); 
            if (previousSet) { //already has a mapping
                splCVEIDMap.set(currentSPL, previousSet.add(cve));
            } else {
                const newSet = new Set();
                newSet.add(cve);
                splCVEIDMap.set(currentSPL, newSet);
            }
        }
    }
    const returnMap = new Map();
    for (const key of splCVEIDMap.keys()) {
        const set = splCVEIDMap.get(key);
        const publishDate = splPublishDateMap.get(key);
        let array = null;
        if (set) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
            const addSet: Record<string, object> = {};
            addSet['CVE_IDs'] = array;
            if (publishDate) {
                addSet['Published_Date'] = publishDate
            }
            returnMap.set(key, addSet);
        }
    }
    return returnMap;
}

export function buildAOSPVersionASBCVEIDTree(tree: any): Map<any, any> {
    const asbCVEIDMap = new Map<string, Set<any>>();
    const aospASBMap = new Map<string, Set<any>>();
    //will create two maps that are later combined
    for (const cve in tree) {
        const tempCVEData = tree[cve];
        if (tempCVEData.ASB && cve) {
            const previousMap = asbCVEIDMap.get(tempCVEData.ASB);
            if (previousMap) { //already has a mapping
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
                    if (previousMap) { //already has a mapping
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
    const returnMap = new Map ();
    for (const key of aospASBMap.keys()) {
        const asbCVEIDSet = aospASBMap.get(key);
        if (asbCVEIDSet) {
            for (const currentEntry of asbCVEIDSet) {
                const set = asbCVEIDMap.get(currentEntry);
                let array = null;
                if (set) {
                    const iterator = set[Symbol.iterator]();
                    array = Array.from(iterator);
                    for (let i = 0; i < array.length; i++) {
                        if (!validCheck.isAndroidVersionSupported(tree, key, array[i])) {
                            //if android version is in aosp version list
                            array.splice(i, 1);
                            i--;
                        }
                    }
                    JSON.parse(JSON.stringify(array));
                }
                const tempKey = key.replace(/\./g, "_"); //keys cannot have periods in RTDB
                const tempArray = [currentEntry, array];
                returnMap.set(tempKey,tempArray);
            }
        }
    }
    return returnMap;
}

export function buildAOSPVersionCVEIDTree(tree: any): Map<string, Set<any>> {
    const aospCVEIDMap = new Map<string, Set<any>>();
    for (const cve in tree) {
        const cveData = tree[cve];
        for (const aospNumber in cveData.aosp_versions) {
            let aospVersion = cveData.aosp_versions[aospNumber];
            aospVersion = aospVersion.replace(/\./g, "_");
            if (cve) {
                const previousSet = aospCVEIDMap.get(aospVersion);
                if (previousSet) { //already has mapping
                    aospCVEIDMap.set(aospVersion, previousSet.add(cve));
                } else {
                    const newSet = new Set();
                    newSet.add(cve);
                    aospCVEIDMap.set(aospVersion, newSet);
                }
            }
        }
    }
    const returnMap = new Map();
    for (const key of aospCVEIDMap.keys()) {
        const set = aospCVEIDMap.get(key);
        let array = null;
        if (set) {
            const iterator = set[Symbol.iterator]();
            array = Array.from(iterator);
            const CVEs = { 'CVE_IDs': array };
            returnMap.set(key, CVEs);
        }
    }
    return returnMap;
}

export function buildBulletinVersionTree(tree: any): Map<string, Array<string>> {
    //Bulletin version tree with latest version stored
    //for each bulletin
    const bulletinVersionMap = new Map<string, Array<string>>();
    for (const cve in tree) {
        const cveData = tree[cve];
        const currentASB = cveData.ASB;
        const currentVersion = cveData.BulletinVersion;
        if (currentASB && currentVersion) {
            const bulletinVersionCurrentValue = bulletinVersionMap.get(currentASB);
            if (bulletinVersionCurrentValue && currentVersion >= bulletinVersionCurrentValue[0]) {
                const arrayToAdd: string[] = [currentVersion, cveData.published_date];
                bulletinVersionMap.set(currentASB, arrayToAdd);
            } else if (bulletinVersionCurrentValue === null || bulletinVersionCurrentValue === undefined) {
                const arrayToAdd: string[] = [currentVersion, cveData.published_date];
                bulletinVersionMap.set(currentASB, arrayToAdd);
            }
        }
    }
    const returnMap = new Map();
    for (const key of bulletinVersionMap.keys()) {
        const addData: Record<string, string> = {};
        const array = bulletinVersionMap.get(key);
        if (array) {
            addData['Latest_Version'] = array[0];
            if (array[1]) {
                addData['Release_Date'] = array[1];
            }
        }
        addData['Bulletin_ID'] = key;
        returnMap.set(key, addData);
    }
    return returnMap;
}
