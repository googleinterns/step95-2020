import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import * as Enumerable from "linq";

export const getAndroidVersion = functions.https.onRequest((request, response) => {
    getSupportedAndroidVersions(response);
  }
);

function getSupportedAndroidVersions(res: any) {
  const today = new Date();
  const dd = String(today.getDate()).padStart(2, "0");
  const mm = String(today.getMonth() + 1).padStart(2, "0");
  const yyyy = today.getFullYear();
  const date = yyyy + "-" + mm + "-" + dd;

  const db = admin.database();
  const ref = db.ref("/AOSP_Version_Data");
  let androidVerData: any;
  const androidVerDataPromise = ref.orderByKey().once("value");
  androidVerDataPromise.then((snapshot) => {
    androidVerData = snapshot.val();
    const keyList = Object.keys(androidVerData);
    const valueList: Array<object> = Object.values(androidVerData);
    let verEndDateList = [];
    for (let i = 0; i < keyList.length; i++) {
    const key = keyList[i];
    const value: object = valueList[i];
    const obj: any = {};
    obj.Version = key;
    obj.Termination_Date = Object.values(value)[1];
    verEndDateList.push(obj);
    }
    verEndDateList = Enumerable.from(verEndDateList)
    .where(function (obj) {return obj.Termination_Date > date;})
    .select(function (obj) {return obj.Version;})
    .toArray();
    const supportedVersion = { supportedVersion: verEndDateList };
    res.send(supportedVersion);
  }).catch((error) => {
    res.status(500).send("error getting supported Android Versions: " + error);
  });
}
