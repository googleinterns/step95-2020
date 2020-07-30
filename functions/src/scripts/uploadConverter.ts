import * as readInputUpload from './readInputUpload';
import * as converterFunction from './converter';

export function getUploadConvert(filePath: string) {
    let bulletinJSON1 = null;
    let version1 = "";
    bulletinJSON1 = readInputUpload.getConvertedInputFile(filePath); //get parsed JSON
    version1 = readInputUpload.getVersion(filePath); //get version of bulletin
    return converterFunction.convert(bulletinJSON1, version1);
}
