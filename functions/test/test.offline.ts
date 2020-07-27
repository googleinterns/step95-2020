import 'mocha';
import * as chai from 'chai';
const assert = chai.assert;
import * as sinon from 'sinon';
import * as admin from 'firebase-admin';
import * as funcTest from "firebase-functions-test";

describe("test ASB api", () => {
  let myFunctions:any, adminInitStub:any;
  const tester = funcTest();
  
  before(async () => {
    adminInitStub = sinon.stub(admin, "initializeApp");
    myFunctions = await import("../src/index");
  });

  after(() => {
    adminInitStub.restore();
    tester.cleanup();
  });

  describe('CVE', () => {

    it('should return bad request for invalid query param', (done) => {

      const req = { query: {cveid: '2015-9016'} };
      const res = {
        send: (result:any) => {
          //None of the following works if uncomment line 45 in CVE/index.ts
          //result.should.have.status(400); 
          //console.log(result);
          assert.equal(result, 'Error: CVE ID is malformed.');
          done();
        }
      };

      myFunctions.getCVEFunction(req, res);

    });
  });

});