export function replacePeriodsWithUnderscores(source: any): void {
    //keys in RTDB cannot have periods
    if (source) {
        for (const versionDataSub of Object.keys(source)) {
            const versionDataSubChanged = versionDataSub.replace(/\./g, "_");
            source[versionDataSubChanged] = source[versionDataSub];
            delete source[versionDataSub];
        }
    }
}
