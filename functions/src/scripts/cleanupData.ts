export function replacePeriodsWithUnderscores(source: any): void {
    if (source) {
        for (const versionDataSub of Object.keys(source)) {
            const versionDataSubChanged = versionDataSub.replace(/\./g, "_");
            source[versionDataSubChanged] = source[versionDataSub];
            delete source[versionDataSub];
        }
    }
}
