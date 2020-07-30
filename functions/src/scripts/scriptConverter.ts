import * as readInputScript from './readInputScript';
import * as config from '../config';
import * as admin from 'firebase-admin';
import * as converterFile from './converter';

admin.initializeApp(config.firebaseConfig);
const bulletinJSON = readInputScript.getConvertedInputFile();
const version = readInputScript.getVersion();
converterFile.convert(bulletinJSON, version).catch(error => {console.log("Error with converter"+ error)});
