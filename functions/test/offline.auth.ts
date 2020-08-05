import 'mocha';
import * as chai from 'chai';
import * as sinon from 'sinon';
import * as admin from 'firebase-admin';
import * as funcTest from 'firebase-functions-test';
import * as usertoken from './userToken';

admin.initializeApp();

describe('testing functions in /grantAdminRole', () => {
    let myFunctions: any, adminInitStub: any;
    const assert = chai.assert
    const expect = chai.expect
    const tester = funcTest();
    
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
            const req = {headers : {'usertoken': usertoken.token}};
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