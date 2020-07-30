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

      if(filePath){
      await bucket.file(filePath).download({destination: tempFilePath});
      }
      console.log('File downloaded locally to', tempFilePath);
      await uploadFile(tempFilePath);
      fs.unlinkSync(tempFilePath);
      
});

function uploadFile(filePath: any): Promise<any>{
    return converterScript.getUploadConvert(filePath);
}