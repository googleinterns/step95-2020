import 'mocha';
import * as chai from 'chai';
import * as sinon from 'sinon';
import * as admin from 'firebase-admin';
import * as funcTest from 'firebase-functions-test';

describe('test functions in /cves', () => {
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
      myFunctions.getCVEFunction(req, res);
    });
  });

  describe('getCvesWithBulletinID()', () => {
    describe('with an invalid Bulletin ID', () => {
      it('should return 400 bad request', (done) => {
        const req = { query: { bulletinid: '2018-2' } };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'Bulletin ID is malformed.');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a non-existent Bulletin ID', () => {
      it('should return 404 not found', (done) => {
        const req = { query: { bulletinid: '2018-13' } };

        noDataStub('/CVEs');

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            expect(result).to.have.string(
              'no CVEs associated with this bulletin'
            );
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a valid Bulletin ID', () => {
      it('should return CVE details', (done) => {
        const req = { query: { bulletinid: '2018-02' } };

        const refParam = '/CVEs';
        const snap = {
          val: () => {
            return {
              'CVE-1': {
                ASB: '2018-01',
              },
              'CVE-2': {
                ASB: '2018-02',
              },
              'CVE-3': {
                ASB: '2018-03',
              },
            };
          },
        };
        getSnapshotStub(refParam, snap);

        const expectedResult = { CVEs: [{ ASB: '2018-02' }] };
        const res = {
          send: (result: any) => {
            assert.deepEqual(result, expectedResult);
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });
  });

  describe('getCvesWithSplID()', () => {
    describe('with an invalid SPL ID', () => {
      it('should return 400 bad request', (done) => {
        const req = { query: { splid: '20182028' } };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'SPL ID is malformed.');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a non-existent SPL ID', () => {
      it('should return 404 not found', (done) => {
        const req = { query: { splid: '2018-02-05' } };

        noDataStub('/CVEs');

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            expect(result).to.have.string('no CVEs associated with this SPL');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a valid SPL ID', () => {
      it('should return CVE details', (done) => {
        const req = { query: { splid: '2018-02-05' } };

        const refParam = '/CVEs';
        const snap = {
          val: () => {
            return {
              'CVE-1': {
                patch_level: '2018-02-01',
              },
              'CVE-2': {
                patch_level: '2018-02-05',
              },
              'CVE-3': {
                patch_level: '2018-03-05',
              },
            };
          },
        };
        getSnapshotStub(refParam, snap);

        const expectedResult = { CVEs: [{ patch_level: '2018-02-05' }] };
        const res = {
          send: (result: any) => {
            assert.deepEqual(result, expectedResult);
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });
  });

  describe('getCVEsBeforeSPL()', () => {
    describe('with an invalid SPLstart ID', () => {
      it('should return 400 bad request', (done) => {
        const req = { query: { splstart: '20180405' } };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'SPL ID is malformed.');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a non-existent SPLstart ID', () => {
      it('should return 404 not found', (done) => {
        const req = { query: { splstart: '2018-02-05' } };

        noDataStub('/CVEs');

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            expect(result).to.have.string('no CVEs associated with this SPL');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a valid SPLstart ID', () => {
      it('should return CVE details', (done) => {
        const req = { query: { splstart: '2018-02-05' } };

        const refParam = '/CVEs';
        const snap = {
          val: () => {
            return {
              'CVE-1': {
                ASB: '2018-02',
              },
              'CVE-2': {
                ASB: '2018-03',
              },
              'CVE-3': {
                ASB: '2018-04',
              },
            };
          },
        };
        getSnapshotStub(refParam, snap);

        const expectedResult = { CVEs: [{ ASB: '2018-02' }] };
        const res = {
          send: (result: any) => {
            assert.deepEqual(result, expectedResult);
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });
  });

  describe('version1And2VulDifference()', () => {
    describe('with an invalid Bulletin ID', () => {
      it('should return 400 bad request', (done) => {
        const req = {
          query: {
            bulletinid: '2018-2',
            v1: '7',
            v2: '8',
          },
        };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'Bulletin ID is malformed.');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with an invalid version number', () => {
      it('should return 400 bad request', (done) => {
        const req = {
          query: {
            bulletinid: '2018-02',
            v1: '7.7',
            v2: '8',
          },
        };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'Version ID is malformed.');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a non-existent Bulletin version', () => {
      it('should return 404 not found', (done) => {
        const req = {
          query: {
            bulletinid: '2018-02',
            v1: '1',
            v2: '2_1',
          },
        };

        noDataStub('/CVE_History');

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            expect(result).to.have.string(
              'no CVEs associated with this bulletin'
            );
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with valid Bulletin versions', () => {
      it('should return CVE ids', (done) => {
        const req = {
          query: {
            bulletinid: '2018-02',
            v1: '1',
            v2: '2_1',
          },
        };

        const refParam = '/CVE_History';
        const snap = {
          val: () => {
            return {
              'CVE-1': {
                '2018-02:1': {
                  CVE: '1',
                },
              },
              'CVE-2': {
                '2018-02:1': {
                  CVE: '2',
                },
                '2018-02:2_1': {
                  CVE: '2',
                },
              },
              'CVE-3': {
                '2018-02:1': {
                  CVE: '3',
                  tech_details: 'old',
                },
                '2018-02:2_1': {
                  CVE: '3',
                  tech_details: 'new',
                },
              },
              'CVE-4': {
                '2018-02:2_1': {
                  CVE: '4',
                },
              },
            };
          },
        };
        getSnapshotStub(refParam, snap);

        const expectedResult = { CVEs: ['1', '4', '3'] };
        const res = {
          send: (result: any) => {
            assert.deepEqual(result, expectedResult);
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });
  });

  describe('getCveWithCveID()', () => {
    describe('with an invalid CVE ID', () => {
      it('should return 400 bad request', (done) => {
        const req = { query: { cveid: '2015-9016' } };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'CVE ID is malformed.');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a non-existent CVE ID', () => {
      it('should return 404 not found', (done) => {
        const req = { query: { cveid: 'CVE-2020-2020' } };

        const refParam = '/CVEs';
        const idParam = req.query.cveid;
        noDataForIDStub(refParam, idParam);

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'CVE ID is not present in the database');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a valid CVE ID', () => {
      it('should return CVE details', (done) => {
        const req = { query: { cveid: 'CVE-2020-2020' } };

        const refParam = '/CVEs';
        const idParam = req.query.cveid;
        const snap = {
          val: () => {
            return { [req.query.cveid]: 'cve details' };
          },
        };
        getSnapshotByIDStub(refParam, idParam, snap);

        const res = {
          send: (result: any) => {
            assert.equal(result, 'cve details');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });
  });

  describe('getChangesBetweenSPLs()', () => {
    describe('with an invalid SPL ID', () => {
      it('should return 400 bad request', (done) => {
        const req = {
          query: {
            spl1: '2018-200',
            spl2: '2018-2002',
          },
        };
        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 400);
            return res;
          },
          send: (result: any) => {
            assert.equal(result, 'SPL ID is malformed.');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a non-existent SPL ID', () => {
      it('should return 404 not found', (done) => {
        const req = {
          query: {
            spl1: '2018-02-05',
            spl2: '2018-04-01',
          },
        };

        noDataStub('/SPL_CVE_IDs');

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            expect(result).to.have.string('no CVEs between these two SPL IDs');
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with valid SPL IDs', () => {
      it('should return changes between SPLs', (done) => {
        const req = {
          query: {
            spl1: '2018-02-05',
            spl2: '2018-04-01',
          },
        };

        const refParam = '/SPL_CVE_IDs';
        const OnceSnap = {
          val: () => {
            return {
              '2018-02-05': {
                CVE_IDs: ['CVE-1'],
                Published_Date: '2018-01-01',
              },
              '2018-03-01': {
                CVE_IDs: ['CVE-2'],
                Published_Date: '2018-01-01',
              },
              '2018-03-05': {
                CVE_IDs: ['CVE-3'],
                Published_Date: '2018-01-01',
              },
              '2018-04-01': {
                CVE_IDs: ['CVE-4'],
                Published_Date: '2018-01-01',
              },
            };
          },
        };
        getDetailSnapForOnceSnapStub(refParam, OnceSnap);

        const expectedResult = {
          CVEs: ['cve details', 'cve details', 'cve details'],
        };
        const res = {
          send: (result: any) => {
            assert.deepEqual(result, expectedResult);
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });
  });

  describe('getCvesWithAndroidVersion()', () => {
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
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a non-existent Android Version', () => {
      it('should return 404 not found', (done) => {
        const req = { query: { androidVersion: '7_7' } };

        const refParam = '/AOSP_Version_CVE_IDs';
        const idParam = req.query.androidVersion;
        noDataForIDStub(refParam, idParam);

        const res = {
          status: (statusCode: any) => {
            assert.equal(statusCode, 404);
            return res;
          },
          send: (result: any) => {
            expect(result).to.have.string(
              'no CVEs associated with this Android Version'
            );
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });

    describe('with a valid Android Version', () => {
      it('should return CVE details', (done) => {
        const req = { query: { androidVersion: '6_0' } };

        const idParam = req.query.androidVersion;
        const refParam = '/AOSP_Version_CVE_IDs';
        const CveIDSnap = {
          val: () => {
            return {
              '6_0': {
                CVE_IDs: ['CVE-1', 'CVE-2'],
              },
              '5_1': {
                CVE_IDs: ['CVE-3'],
              },
            };
          },
        };
        getDetailSnapForIDSnapStub(idParam, refParam, CveIDSnap);

        const expectedResult = { CVEs: ['cve details', 'cve details'] };
        const res = {
          send: (result: any) => {
            assert.deepEqual(result, expectedResult);
            done();
          }
        };
        myFunctions.getCVEFunction(req, res);
      });
    });
  });

  const CveDetailsSnap = {
    val: () => {
      return 'cve details';
    },
  };

  function noDataStub(refParam: string) {
    const snap = { val: () => undefined };
    getSnapshotStub(refParam, snap);
  }

  function noDataForIDStub(refParam: string, idParam: string) {
    const snap = { val: () => undefined };
    getSnapshotByIDStub(refParam, idParam, snap);
  }

  function getSnapshotStub(refParam: string, snap: any) {
    const refStub = sinon.stub();
    const onceStub = sinon.stub();
    databaseStub.returns({ ref: refStub });
    refStub.withArgs(refParam).returns({ once: onceStub });
    onceStub.withArgs('value').returns(Promise.resolve(snap));
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

  function getDetailSnapForOnceSnapStub(refParam: string, snap: any) {
    const refStub = sinon.stub();
    const onceStub1 = sinon.stub();
    const onceStub2 = sinon.stub();;
    const orderByKey = sinon.stub();
    const equalToStubAny = sinon.stub();

    databaseStub.returns({ ref: refStub });
    refStub.withArgs(refParam).returns({ once: onceStub1 });
    onceStub1.withArgs('value').returns(Promise.resolve(snap));

    refStub.withArgs('/CVEs').returns({ orderByKey: orderByKey });
    orderByKey.returns({ equalTo: equalToStubAny });
    equalToStubAny.withArgs(sinon.match.any).returns({ once: onceStub2 });
    onceStub2.withArgs('value').returns(Promise.resolve(CveDetailsSnap));
  }

  function getDetailSnapForIDSnapStub(idParam: any, refParam: string, snap: any) {
    const refStub = sinon.stub();
    const onceStub1 = sinon.stub();
    const onceStub2 = sinon.stub();
    const orderByKey1 = sinon.stub();
    const orderByKey2 = sinon.stub();
    const equalToStub = sinon.stub();
    const equalToStubAny = sinon.stub();

    databaseStub.returns({ ref: refStub });
    refStub.withArgs(refParam).returns({ orderByKey: orderByKey1 });
    orderByKey1.returns({ equalTo: equalToStub });
    equalToStub.withArgs(idParam).returns({ once: onceStub1 });
    onceStub1.withArgs('value').returns(Promise.resolve(snap));

    refStub.withArgs('/CVEs').returns({ orderByKey: orderByKey2 });
    orderByKey2.returns({ equalTo: equalToStubAny });
    equalToStubAny.withArgs(sinon.match.any).returns({ once: onceStub2 });
    onceStub2.withArgs('value').returns(Promise.resolve(CveDetailsSnap));
  }
});