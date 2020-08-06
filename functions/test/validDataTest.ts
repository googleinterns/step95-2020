import 'mocha';
import * as chai from 'chai';

describe('Test valid data functions', () => {
  let myFunctions: any;

  before (async () => {
    myFunctions = await import ('../src/scripts/validData');
  })

  describe('check cve id validity with escape character', () => {
    it('should return id without escape character', () => {
      const data = 'CVE-2017-13228\n';
      const regex = /^CVE-\d{4}-\d{3,7}$/;     

      const outputData = myFunctions.checkCVEValidity(data, regex);
      const composedData = ['CVE-2017-13228'];

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check cve id validity with two ids in one slot', () => {
    it('should return both ids separated', () => {
      const data = 'CVE-2017-13228, CVE-2017-13229';
      const regex = /^CVE-\d{4}-\d{3,7}$/;     

      const outputData = myFunctions.checkCVEValidity(data, regex);
      const composedData = ['CVE-2017-13228', 'CVE-2017-13229'];

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check cve id validity with extra text', () => {
    it('should return id without extra text', () => {
      const data = 'CVE-2017-13228 (extra text)';
      const regex = /^CVE-\d{4}-\d{3,7}$/;     

      const outputData = myFunctions.checkCVEValidity(data, regex);
      const composedData = ['CVE-2017-13228'];

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check version num with old version with multiple digits being sent to db', () => {
    it('should return false', () => {
      const version = "1_1";
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228", "BulletinVersion": "2_1"}
      };
      const json = {"CVE-2017-13228": {"CVE": "CVE-2017-13228"}}
      const outputData = myFunctions.validVersionNumber(version, currentTree, json);
      const composedData = false;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check version num with old version with single digit being sent to db', () => {
    it('should return false', () => {
      const version = "1";
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228", "BulletinVersion": "2"}
      };
      const json = {"CVE-2017-13228": {"CVE": "CVE-2017-13228"}}
      const outputData = myFunctions.validVersionNumber(version, currentTree, json);
      const composedData = false;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check version num with new version with multiple digits being sent to db', () => {
    it('should return true', () => {
      const version = "2_1";
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228", "BulletinVersion": "1_1"}
      };
      const json = {"CVE-2017-13228": {"CVE": "CVE-2017-13228"}}
      const outputData = myFunctions.validVersionNumber(version, currentTree, json);
      const composedData = true;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check version num with new version with single digits being sent to db', () => {
    it('should return true', () => {
      const version = "2";
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228", "BulletinVersion": "1"}
      };
      const json = {"CVE-2017-13228": {"CVE": "CVE-2017-13228"}}
      const outputData = myFunctions.validVersionNumber(version, currentTree, json);
      const composedData = true;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check version num with new version with mix of number of digits being sent to db', () => {
    it('should return true', () => {
      const version = "2_1";
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228", "BulletinVersion": "1"}
      };
      const json = {"CVE-2017-13228": {"CVE": "CVE-2017-13228"}}
      const outputData = myFunctions.validVersionNumber(version, currentTree, json);
      const composedData = true;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check version num with new version with mix of number of digits being sent to db', () => {
    it('should return false', () => {
      const version = "1";
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228", "BulletinVersion": "2_1"}
      };
      const json = {"CVE-2017-13228": {"CVE": "CVE-2017-13228"}}
      const outputData = myFunctions.validVersionNumber(version, currentTree, json);
      const composedData = false;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check if android version is supported with null aosp version', () => {
    it('should return false', () => {
      const id = "CVE-2017-13228"
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228"}
      };
      const aospVersion = "5.1.1";
      const outputData = myFunctions.isAndroidVersionSupported(currentTree, aospVersion, id);
      const composedData = false;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check if android version is supported with missing aosp version', () => {
    it('should return false', () => {
      const id = "CVE-2017-13228"
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228", "aosp_versions": ["6.0", "6.0.1"]}
      };
      const aospVersion = "5.1.1";
      const outputData = myFunctions.isAndroidVersionSupported(currentTree, aospVersion, id);
      const composedData = false;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check if android version is supported with valid aosp version', () => {
    it('should return true', () => {
      const id = "CVE-2017-13228"
      const currentTree = {
        'CVE-2017-13228': {"CVE": "CVE-2017-13228", "aosp_versions": ["5.1.1", "6.0", "6.0.1"]}
      };
      const aospVersion = "5.1.1";
      const outputData = myFunctions.isAndroidVersionSupported(currentTree, aospVersion, id);
      const composedData = true;

      chai.assert.deepEqual(outputData, composedData);
    });
  });
});