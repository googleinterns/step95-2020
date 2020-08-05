import 'mocha';
import * as chai from 'chai';
import * as sinon from 'sinon';
import * as admin from 'firebase-admin';
import * as funcTest from 'firebase-functions-test';

describe('test functions in /androidVersions', () => {
  let myFunctions: any, adminInitStub: any;
  const tester = funcTest();
  const databaseStub = sinon.stub();
  const assert = chai.assert;

  before(async () => {
    adminInitStub = sinon.stub(admin, 'initializeApp');
    Object.defineProperty(admin, 'database', { get: () => databaseStub });
    myFunctions = await import('../src/index');
  });

  after(() => {
    adminInitStub.restore();
    tester.cleanup();
  });

  describe('getSupportedAndroidVersions()', () => {
    it('should return a list of supported Android Versions', (done) => {
      const req = {};

      const refParam = '/AOSP_Version_Data';
      const snap = {
        val: () => {
          return {
            '9': { Release_Date: '2018-08', Termination_Date: '2099-01-31' },
            '10': { Release_Date: '2019-09', Termination_Date: '2099-02-28' },
            '4_4': { Release_Date: '2013-10', Termination_Date: '2017-10-31' },
            '5_1': { Release_Date: '2015-03', Termination_Date: '2018-03-31' },
          };
        },
      };
      getSnapshotStub(refParam, snap);

      const expectedResult = { supportedVersion: ['9', '10'] };
      const res = {
        send: (result: any) => {
          assert.deepEqual(result, expectedResult);
          done();
        },
      };
      myFunctions.getAndroidVersionFunction(req, res);
    });
  });

  function getSnapshotStub(refParam: string, snap: any) {
    const refStub = sinon.stub();
    const orderByKeyStub = sinon.stub();
    const onceStub = sinon.stub();
    databaseStub.returns({ ref: refStub });
    refStub.withArgs(refParam).returns({ orderByKey: orderByKeyStub });
    orderByKeyStub.returns({ once: onceStub });
    onceStub.withArgs('value').returns(Promise.resolve(snap));
  }
});
