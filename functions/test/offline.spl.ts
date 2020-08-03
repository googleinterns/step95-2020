import 'mocha';
import * as chai from 'chai';
import * as sinon from 'sinon';
import * as admin from 'firebase-admin';
import * as funcTest from 'firebase-functions-test';

describe('test functions in /spls', () => {
  let myFunctions: any, adminInitStub: any;
  const tester = funcTest();
  const databaseStub = sinon.stub();
  const assert = chai.assert;
  const expect = chai.expect;

  before(async () => {
    adminInitStub = sinon.stub(admin, 'initializeApp');
    Object.defineProperty(admin, 'database', { get: () => databaseStub });
    myFunctions = await import('../src/index');
  });

  after(() => {
    adminInitStub.restore();
    tester.cleanup();
  });

  describe('without query params', () => {
    it('should return 400 bad request', (done) => {
      const req = { query: {} };
      const res = {
        status: (statusCode: any) => {
          assert.equal(statusCode, 400);
          return res;
        },
        send: (result: any) => {
          expect(result).to.have.string('No valid parameters specified');
          done();
        },
      };
      myFunctions.getSPLFunction(req, res);
    });
  });

  describe('getSplsWithBulletinID()', () => {
    describe('with an invalid Bulletin ID', () => {
      it('should return 400 bad request', (done) => {
        const req = { query: { bulletinid: '2018' } };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'Bulletin ID is malformed.');
            done();
          },
        };
        myFunctions.getSPLFunction(req, res);
      });
    });

    describe('with a non-existent Bulletin ID', () => {
      it('should return 404 not found', (done) => {
        const req = { query: { bulletinid: '2018-02' } };

        const refParam = '/Bulletin_SPL';
        const idParam = req.query.bulletinid;
        noDataForIDStub(refParam, idParam);

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            expect(result).to.have.string(
              'no SPL data associated with this bulletin'
            );
            done();
          },
        };
        myFunctions.getSPLFunction(req, res);
      });
    });

    describe('with a valid Bulletin ID', () => {
      it('should return a list of SPLs', (done) => {
        const req = { query: { bulletinid: '2018-02' } };

        const refParam = '/Bulletin_SPL';
        const idParam = req.query.bulletinid;
        const snap = {
          val: () => {
            return { '2018-02': ['2018-02-05', '2018-02-01'] };
          },
        };
        getSnapshotByIDStub(refParam, idParam, snap);

        const expectedResult = { Spls: ['2018-02-05', '2018-02-01'] };
        const res = {
          send: (result: any) => {
            assert.deepEqual(result, expectedResult);
            done();
          },
        };
        myFunctions.getSPLFunction(req, res);
      });
    });
  });

  describe('getSplsWithAndroidVersion()', () => {
    describe('with an invalid Android Version', () => {
      it('should return 400 bad request', (done) => {
        const req = { query: { androidVersion: '7.7' } };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'Android Version ID is malformed.');
            done();
          },
        };
        myFunctions.getSPLFunction(req, res);
      });
    });

    describe('with a non-existent Android Version', () => {
      it('should return 404 not found', (done) => {
        const req = { query: { androidVersion: '8_1' } };

        const refParam = '/AOSP_Version_ASB_CVE_IDs';
        const idParam = req.query.androidVersion;
        noDataForIDStub(refParam, idParam);

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            expect(result).to.have.string(
              'no SPLs associated with this Android Version'
            );
            done();
          },
        };
        myFunctions.getSPLFunction(req, res);
      });
    });

    describe('with a valid Android Version', () => {
      it('should return a list of SPLs', (done) => {
        const req = { query: { androidVersion: '8_1' } };

        const refParam1 = '/AOSP_Version_ASB_CVE_IDs';
        const refParam2 = '/Bulletin_SPL';
        const idParam = req.query.androidVersion;
        const snap1 = {
          val: () => {
            return {
              '8_1': {
                '2018-02': ['CVE-1', 'CVE-2'],
                '2018-03': ['CVE-3'],
              },
            };
          },
        };

        const snap2 = {
          val: () => {
            return {
              '2018-02': ['spl1', 'spl2'],
              '2018-03': ['spl3', 'spl4'],
            };
          },
        };
        getSnapshotsFromSnapshotStub(
          idParam,
          refParam1,
          snap1,
          refParam2,
          snap2
        );

        const expectedResult = { Spls: ['spl1', 'spl2', 'spl3', 'spl4'] };
        const res = {
          send: (result: any) => {
            assert.deepEqual(result, expectedResult);
            done();
          },
        };
        myFunctions.getSPLFunction(req, res);
      });
    });
  });

  function noDataForIDStub(refParam: string, idParam: string) {
    const snap = { val: () => undefined };
    getSnapshotByIDStub(refParam, idParam, snap);
  }

  function getSnapshotByIDStub(refParam: string, idParam: any, snap: any) {
    const refStub = sinon.stub();
    const orderByKeyStub = sinon.stub();
    const equalToStub = sinon.stub();
    const onceStub = sinon.stub();
    databaseStub.returns({ ref: refStub });
    refStub.withArgs(refParam).returns({ orderByKey: orderByKeyStub });
    orderByKeyStub.returns({ equalTo: equalToStub });
    equalToStub.withArgs(idParam).returns({ once: onceStub });
    onceStub.withArgs('value').returns(Promise.resolve(snap));
  }

  function getSnapshotsFromSnapshotStub(
    idParam: any,
    refParam1: string,
    snap1: any,
    refParam2: string,
    snap2: any
  ) {
    const refStub = sinon.stub();
    const onceStub1 = sinon.stub();
    const onceStub2 = sinon.stub();
    const orderByKey1 = sinon.stub();
    const orderByKey2 = sinon.stub();
    const equalToStub = sinon.stub();
    const equalToStubAny = sinon.stub();

    databaseStub.returns({ ref: refStub });
    refStub.withArgs(refParam1).returns({ orderByKey: orderByKey1 });
    orderByKey1.returns({ equalTo: equalToStub });
    equalToStub.withArgs(idParam).returns({ once: onceStub1 });
    onceStub1.withArgs('value').returns(Promise.resolve(snap1));

    refStub.withArgs(refParam2).returns({ orderByKey: orderByKey2 });
    orderByKey2.returns({ equalTo: equalToStubAny });
    equalToStubAny.withArgs(sinon.match.any).returns({ once: onceStub2 });
    onceStub2.withArgs('value').returns(Promise.resolve(snap2));
  }
});
