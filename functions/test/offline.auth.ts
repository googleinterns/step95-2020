import 'mocha';
import * as chai from 'chai';
import * as sinon from 'sinon';
import * as admin from 'firebase-admin';
import * as funcTest from 'firebase-functions-test';

admin.initializeApp();

describe('testing functions in /grantAdminRole', () => {
    let myFunctions: any, adminInitStub: any;
    const assert = chai.assert
    const expect = chai.expect
    const tester = funcTest();
    
    const token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImYwNTQxNWIxM2FjYjk1OTBmNzBkZjg2Mjc2NWM2NTVmNWE3YTAxOWUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMjU1NTk0MDU1OS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjMyNTU1OTQwNTU5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE0OTA4MTk2NzQzMDE0MTM2ODY0IiwiaGQiOiJnb29nbGUuY29tIiwiZW1haWwiOiJuemJ1dGxlckBnb29nbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJuLTFHMnNRR3lmUExSelBpUTdJeFN3IiwiaWF0IjoxNTk2NzMyMzQ5LCJleHAiOjE1OTY3MzU5NDl9.Xr_UWKuSchr6W4ngH--lJXB0zfWcLESo8MoCe9gqyLsnWSFnjpDKYYiayWmtwJ3rFS17Qbp5WHM0PnARWiFcLcf4Z5EWsM_HkXWSOyfUr2CZYd_zg15-_j3gy-TwfLw6DKpKcsOglsNzst4ThIM-5n1mzJiT5LFS88IFxNNwVSlWCvTDxUEOtTXy-dlZICqSeAoe5srGB_nXtSdwJYZXy35KoOxjtdd_aA1LyhSmQYjGxUc-yUbbdQIvYb9T3exCcm_NPOXRh87mRfEKM4E5i18mzuQpu9lmRibpv7cox8oe6MPDPDMQc9BPgOnt0QIeSKYimmC44ILTctGhREQw2Q';

    before(() => {
        adminInitStub = sinon.stub(admin, 'initializeApp');
        myFunctions = require('../src/index');
    });

    after(() => {
        adminInitStub.restore();
        tester.cleanup();
    });

    describe('noToken', () => {
        it('should return 400 result', (done) => {
            const req = {};
            const res = {
                status: (statusCode: any) => {
                    assert.equal(statusCode, 400);
                    return res;
                },
                send: (result: any) => {
                    expect(result).to.have.string("User's token is not provided");
                    done();
                },
            };
            myFunctions.grantAdminRole(req, res);
        })
    })

    describe('invalidToken', () => {
        it('should return 400 result', (done) => {
            const req = {headers: {'usertoken': '42Jd6pMds'}};
            const res = {
                status: (statusCode: any) => {
                    assert.equal(statusCode, 400);
                    return res;
                },
                send: (result: any) => {
                    expect(result).to.have.string('Error verifying token');
                    done();
                },
            };
            myFunctions.grantAdminRole(req, res);
        })
    })

    describe('expiredToken', () => {
        it('should return expired token error', (done) => {
            const req = {headers : {'usertoken': token}};
            const res = {
                status: (statusCode: any) => {
                    assert.equal(statusCode, 400);
                    return res;
                },
                send: (result: any) => {
                    expect(result).to.have.string('Expired');
                    done();
                },
            };
            myFunctions.grantAdminRole(req, res);
        })
    })
});