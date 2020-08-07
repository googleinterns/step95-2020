//This file saves the JSON file to firebase storage and downloads it  to temporary path

import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as converterScript from '../scripts/uploadConverter';

export const getUpload = functions.storage.object().onFinalize(async (object) => {
    const path = require('path');
    const os = require('os');
    const fs = require('fs');
    const fileBucket = object.bucket; // The Storage bucket that contains the file.
    const filePath = object.name; // File path in the bucket.

    const fileName = path.basename(filePath);

    const bucket = admin.storage().bucket(fileBucket);
    const tempFilePath = path.join(os.tmpdir(), fileName);

    if (filePath) {
        await bucket.file(filePath).download({ destination: tempFilePath });
    }
    console.log('File downloaded locally to', tempFilePath);
    await converterScript.getUploadConvert(tempFilePath);
    fs.unlinkSync(tempFilePath); //remove temp file

});
