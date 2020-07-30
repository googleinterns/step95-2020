import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';
import * as Enumerable from 'linq';

export const accountCreate = functions.auth.user().onCreate(user => {
    const email = user.email;
    const db = admin.database();
    const ref = db.ref('/Email_list');
    return ref.push(email);          
});

const sgMail = require('@sendgrid/mail');
const API_KEY = functions.config().sendgrid.key;
sgMail.setApiKey(API_KEY);

export const notifyNewRelease = functions.database.ref('/Bulletin_Version/{bulletinid}').onCreate((snap,context) => {
    const newBulletin = snap.val();
    const db = admin.database();
    const ref = db.ref('/Email_list');
    const emailListPromise = ref.once('value')
    emailListPromise.then((snapshot) => {
        let emailList = snapshot.val();
        emailList = Enumerable.from(emailList)
        .select(function (obj) { return obj.value })
        .toArray();

        const msg = {
            to: emailList,
            from: 'android-security@google.com',
            subject: 'New release of bulletin',
            text: String(JSON.stringify(newBulletin))
        }
        
        return sgMail.send(msg);

    }).catch(error => {
        console.log("error sending emails for a new bulletin release: " + error)
    });
   });

export const notifyNewVersion = functions.database.ref('/Bulletin_Version/{bulletinid}').onUpdate((change,context) => {
    const updateOnBulletin = change.after.val();
    const db = admin.database();
    const ref = db.ref('/Email_list');
    const emailListPromise = ref.once('value')
    emailListPromise.then((snapshot) => {
        let emailList = snapshot.val();
        emailList = Enumerable.from(emailList)
        .select(function (obj) { return obj.value })
        .toArray();

        const msg = {
            to: emailList,
            from: 'android-security@google.com',
            subject: 'Update on bulletin',
            text: String(JSON.stringify(updateOnBulletin))
        }
        
        return sgMail.send(msg);

    }).catch(error => {
        console.log("error sending emails for a new bulletin version: " + error)
    });
});




