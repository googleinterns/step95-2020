export function checkCVEValidity(ID: string, regExpression: any): any {
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
        if (regExpression.test(trimmedID)) {
            finalID.push(trimmedID);
        }
        return finalID;
    }
    return finalID;
}

export function validVersionNumber(versionNum: string, tree: any, JSONData: any): boolean {
    //check if bulletin version being sent is older than current version
    const initalID = Object.keys(JSONData)[0];
    if (tree[initalID] === null || tree[initalID] === undefined) {
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

export function isAndroidVersionSupported(tree: any, aospVersion: string, ID: string): boolean {
    const data = tree[ID];
    if (data.aosp_versions !== undefined) {
        if (Object.values(data.aosp_versions).indexOf(aospVersion) !== -1) {
            return true;
        }
    }
    return false;
}
