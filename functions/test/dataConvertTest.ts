//This file tests the data conversion file

import 'mocha';
import * as chai from 'chai';

describe('Test data converter functions', () => {
  let myFunctions: any;

  before (async () => {
    myFunctions = await import ('../src/scripts/dataConvert');
  })

  describe('valid id for getCVEs', () => {
    it('should return converted cve tree data', () => {
      const mockData = {
        "published": "2018-01-01", "vulnerabilities": [{
          "ASB": "2018-02", "CVE": "CVE-2017-13228", "area": "Platform", "component": "Media framework", "subcomponent": "Avcdec",
          "patch_level": "2018-02-01", "android_id": "A-69478425", "type": "RCE", "severity": "Critical",
          "aosp_versions": ["6.0", "6.0.1", "7.0", "7.1.1", "7.1.2", "8.0", "8.1"]
        }]
      };
      const outputData = myFunctions.getCVEs(mockData, "1");
      const objectBV = Object("1");
      const composedData = {
        'CVE-2017-13228': {
          'published_date': '2018-01-01', 'BulletinVersion': objectBV, 'ASB': '2018-02', 'CVE': 'CVE-2017-13228',
          'area': 'Platform', 'component': 'Media framework', 'subcomponent': 'Avcdec', 'patch_level': '2018-02-01', 'android_id': 'A-69478425', 'type': 'RCE',
          'severity': 'Critical', 'aosp_versions': ['6.0', '6.0.1', '7.0', '7.1.1', '7.1.2', '8.0', '8.1']
        }
      };
      chai.assert.deepEqual(outputData, composedData);

    });
  });

  describe('malformed escape character id for getCVEs', () => {
    it('should return converted cve tree data', () => {
      const mockData = {
        "published": "2018-01-01", "vulnerabilities": [{
          "ASB": "2018-02", "CVE": "CVE-2017-13228\n", "area": "Platform", "component": "Media framework", "subcomponent": "Avcdec",
          "patch_level": "2018-02-01", "android_id": "A-69478425", "type": "RCE", "severity": "Critical",
          "aosp_versions": ["6.0", "6.0.1", "7.0", "7.1.1", "7.1.2", "8.0", "8.1"]
        }]
      };
      const outputData = myFunctions.getCVEs(mockData, "1");
      const objectBV = Object("1");
      const composedData = {
        'CVE-2017-13228': {
          'published_date': '2018-01-01', 'BulletinVersion': objectBV, 'ASB': '2018-02', 'CVE': 'CVE-2017-13228',
          'area': 'Platform', 'component': 'Media framework', 'subcomponent': 'Avcdec', 'patch_level': '2018-02-01', 'android_id': 'A-69478425', 'type': 'RCE',
          'severity': 'Critical', 'aosp_versions': ['6.0', '6.0.1', '7.0', '7.1.1', '7.1.2', '8.0', '8.1']
        }
      };
      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('malformed multipe ids for getCVEs', () => {
    it('should return converted cve tree data', () => {
      const mockData = {
        "published": "2018-01-01", "vulnerabilities": [{
          "ASB": "2018-02", "CVE": "CVE-2017-13228, CVE-2017-13229", "area": "Platform", "component": "Media framework", "subcomponent": "Avcdec",
          "patch_level": "2018-02-01", "android_id": "A-69478425", "type": "RCE", "severity": "Critical",
          "aosp_versions": ["6.0", "6.0.1", "7.0", "7.1.1", "7.1.2", "8.0", "8.1"]
        }]
      };
      const outputData = myFunctions.getCVEs(mockData, "1");
      const objectBV = Object("1");
      const objectID1 = Object("CVE-2017-13228");
      const objectID2 = Object("CVE-2017-13229");
      const composedData = {
        'CVE-2017-13228': {
          'published_date': '2018-01-01', 'BulletinVersion': objectBV, 'ASB': '2018-02', 'CVE': objectID1,
          'area': 'Platform', 'component': 'Media framework', 'subcomponent': 'Avcdec', 'patch_level': '2018-02-01', 'android_id': 'A-69478425', 'type': 'RCE',
          'severity': 'Critical', 'aosp_versions': ['6.0', '6.0.1', '7.0', '7.1.1', '7.1.2', '8.0', '8.1']
        }, 
        'CVE-2017-13229': {
          'published_date': '2018-01-01', 'BulletinVersion': objectBV, 'ASB': '2018-02', 'CVE': objectID2,
          'area': 'Platform', 'component': 'Media framework', 'subcomponent': 'Avcdec', 'patch_level': '2018-02-01', 'android_id': 'A-69478425', 'type': 'RCE',
          'severity': 'Critical', 'aosp_versions': ['6.0', '6.0.1', '7.0', '7.1.1', '7.1.2', '8.0', '8.1']
        }
      };
      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('malformed extra text ids for getCVEs', () => {
    it('should return converted cve tree data', () => {
      const mockData = {
        "published": "2018-01-01", "vulnerabilities": [{
          "ASB": "2018-02", "CVE": "CVE-2017-13228 (extra)", "area": "Platform", "component": "Media framework", "subcomponent": "Avcdec",
          "patch_level": "2018-02-01", "android_id": "A-69478425", "type": "RCE", "severity": "Critical",
          "aosp_versions": ["6.0", "6.0.1", "7.0", "7.1.1", "7.1.2", "8.0", "8.1"]
        }]
      };
      const outputData = myFunctions.getCVEs(mockData, "1");
      const objectBV = Object("1");
      const composedData = {
        'CVE-2017-13228': {
          'published_date': '2018-01-01', 'BulletinVersion': objectBV, 'ASB': '2018-02', 'CVE': 'CVE-2017-13228',
          'area': 'Platform', 'component': 'Media framework', 'subcomponent': 'Avcdec', 'patch_level': '2018-02-01', 'android_id': 'A-69478425', 'type': 'RCE',
          'severity': 'Critical', 'aosp_versions': ['6.0', '6.0.1', '7.0', '7.1.1', '7.1.2', '8.0', '8.1']
        }
      };
      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check build bulletin spl tree ', () => {
    it('should return converted data', () => {
      const mockData = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "patch_level": "2018-02-01"
        }, 
        'CVE-2017-13229': {
          "ASB": "2018-02"
        },
        'CVE-2017-13230': {
          "ASB": "2018-02", "patch_level": "2018-02-05"
        }, 
        'CVE-2017-13231': {
          "ASB": "2018-03"
        }
    }
      const outputData = myFunctions.buildBulletinSPLTree(mockData);
      const composedData = new Map();
      const array1 = ["2018-02-01", "2018-02-05"];
      const array2 = ["2018-03-01"];
      composedData.set("2018-02", array1);
      composedData.set("2018-03", array2);
      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check build spl cve id tree ', () => {
    it('should return converted data', () => {
      const mockData = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "patch_level": "2018-02-01", "published_date": "2018-01-01"
        }, 
        'CVE-2017-13229': {
          "ASB": "2018-02", "published_date": "2018-01-01"
        },
        'CVE-2017-13230': {
          "ASB": "2018-02", "patch_level": "2018-02-05","published_date": "2018-01-01"
        }, 
        'CVE-2017-13231': {
          "ASB": "2018-03", "published_date": "2018-02-01"
        }
    }
      const outputData = myFunctions.buildSPLCVEIDTree(mockData);
      const composedData = new Map ();

      const CVEID1 = ['CVE-2017-13228', 'CVE-2017-13229']
      const addSet1: Record<string, any> = {};
      addSet1['CVE_IDs'] = CVEID1; 
      addSet1['Published_Date'] = "2018-01-01";
      composedData.set("2018-02-01", addSet1);

      const CVEID2 = ['CVE-2017-13230'];
      const addSet2: Record<string, any> = {};
      addSet2['CVE_IDs'] = CVEID2;
      addSet2['Published_Date'] = "2018-01-01";
      composedData.set("2018-02-05", addSet2);

      const CVEID3 = ['CVE-2017-13231'];
      const addSet3: Record<string, any> = {};
      addSet3['CVE_IDs'] = CVEID3;
      addSet3['Published_Date'] = "2018-02-01";
      composedData.set("2018-03-01", addSet3);

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check build aosp version asb cve id tree ', () => {
    it('should return converted data', () => {
      const mockData = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "patch_level": "2018-02-01", "aosp_versions": ["5.1.1", "6.0"]
        }, 
        'CVE-2017-13229': {
          "ASB": "2018-02", "aosp_versions": ["6.0", "6.0.1"]
        },
        'CVE-2017-13230': {
          "ASB": "2018-02", "patch_level": "2018-02-05","aosp_versions": ["5.1.1", "7.0"]
        }
    }
      const outputData = myFunctions.buildAOSPVersionASBCVEIDTree(mockData);
      const composedData = new Map ();

      const cveID1 = ["CVE-2017-13228", "CVE-2017-13230"];
      const asbCVEIDArray = ["2018-02", cveID1];
      composedData.set("5_1_1", asbCVEIDArray);

      const cveID2 = ["CVE-2017-13228", "CVE-2017-13229"];
      const asbCVEIDArray2 = ["2018-02", cveID2];
      composedData.set("6_0", asbCVEIDArray2);

      const cveID3 = ["CVE-2017-13229"];
      const asbCVEIDArray3 = ["2018-02", cveID3];
      composedData.set("6_0_1", asbCVEIDArray3);

      const cveID4 = ["CVE-2017-13230"];
      const asbCVEIDArray4 = ["2018-02", cveID4];
      composedData.set("7_0", asbCVEIDArray4);

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check build aosp version cve id tree ', () => {
    it('should return converted data', () => {
      const mockData = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "patch_level": "2018-02-01", "aosp_versions": ["5.1.1", "6.0"]
        }, 
        'CVE-2017-13229': {
          "ASB": "2018-02", "aosp_versions": ["6.0", "6.0.1"]
        },
        'CVE-2017-13230': {
          "ASB": "2018-02", "patch_level": "2018-02-05","aosp_versions": ["5.1.1", "7.0"]
        },
        'CVE-2017-13231': {
          "ASB": "2018-03", "patch_level": "2018-03-01", "aosp_versions": ["6.0.1", "7.0", "8.0"]
        }
    }
      const outputData = myFunctions.buildAOSPVersionCVEIDTree(mockData);
      const composedData = new Map ();

      const cveIDArray1 = ["CVE-2017-13228", "CVE-2017-13230"];
      const cveIDLabeled = {"CVE_IDs": cveIDArray1};
      composedData.set("5_1_1", cveIDLabeled);

      const cveIDArray2 = ["CVE-2017-13228", "CVE-2017-13229"];
      const cveIDLabeled2 = {"CVE_IDs": cveIDArray2};
      composedData.set("6_0", cveIDLabeled2);

      const cveIDArray3 = ["CVE-2017-13229", "CVE-2017-13231"];
      const cveIDLabeled3 = {"CVE_IDs": cveIDArray3};
      composedData.set("6_0_1", cveIDLabeled3);

      const cveIDArray4 = ["CVE-2017-13230", "CVE-2017-13231"];
      const cveIDLabeled4 = {"CVE_IDs": cveIDArray4};
      composedData.set("7_0", cveIDLabeled4);

      const cveIDArray5 = ["CVE-2017-13231"];
      const cveIDLabeled5 = {"CVE_IDs": cveIDArray5};
      composedData.set("8_0", cveIDLabeled5);

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check build bulletin version tree ', () => {
    it('should return converted data', () => {
      const mockData = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1"
        }, 
        'CVE-2017-13229': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1"
        },
        'CVE-2017-13230': {
          "ASB": "2018-02", "published_date": "2018-01-01","BulletinVersion": "1_1"
        },
        'CVE-2017-13231': {
          "ASB": "2018-03", "published_date": "2018-02-01", "BulletinVersion": "1"
        }
    }
      const outputData = myFunctions.buildBulletinVersionTree(mockData);
      const composedData = new Map ();

      const composedMetaData1 = {
        "Latest_Version": "1_1",
        "Release_Date": "2018-01-01",
        "Bulletin_ID":"2018-02"
      }

      composedData.set("2018-02", composedMetaData1);

      const composedMetaData2 = {
        "Latest_Version": "1",
        "Release_Date": "2018-02-01",
        "Bulletin_ID": "2018-03"
      }

      composedData.set("2018-03", composedMetaData2);

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check build cve history tree with no history tree', () => {
    it('should return converted data', () => {
      const tree = null; 
      const versionHistory = "1_1";
      const cveTree = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1", "android_id": "A-67713100"
        }, 
        'CVE-2017-13229': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1", "android_id": "A-77713100"
        },
        'CVE-2017-13230': {
          "ASB": "2018-02", "published_date": "2018-01-01","BulletinVersion": "1_1", "android_id": "A-87713100"
        },
        'CVE-2017-13231': {
          "ASB": "2018-03", "published_date": "2018-02-01", "BulletinVersion": "3", "android_id": "A-97713100"
        }
    }
      const jsonData = {"CVE-2017-13228": {"ASB": "2018-02"}};

      const outputData = myFunctions.buildCVEHistoryTree(tree, versionHistory, cveTree, jsonData);
      const composedData = new Map ();

      const cveID1Composed = ["2018-02:1", {"ASB": "2018-02", "published_date": "2018-01-01", 
          "android_id": "A-67713100"}];
      composedData.set("CVE-2017-13228", cveID1Composed);

      const cveID2Composed = ["2018-02:1", {"ASB": "2018-02", "published_date": "2018-01-01", 
          "android_id": "A-77713100"}];
      composedData.set("CVE-2017-13229", cveID2Composed);

      const cveID3Composed = ["2018-02:1_1", {"ASB": "2018-02", "published_date": "2018-01-01",
          "android_id": "A-87713100"}];
      composedData.set("CVE-2017-13230", cveID3Composed);

      const cveID4Composed = ["2018-03:3", {"ASB": "2018-03", "published_date": "2018-02-01",
          "android_id": "A-97713100"}];
      composedData.set("CVE-2017-13231", cveID4Composed);

      const composedArray = [composedData];

      chai.assert.deepEqual(outputData, composedArray);
    });
  });

  describe('check build cve history tree with history tree', () => {
    it('should return converted data', () => {
      const tree = {
        'CVE-2017-13229': {
          '2018-02:1': {
            "ASB": "2018-02", "published_date": "2018-01-01", "android_id": "A-77713100", 
            "CVE": "CVE-2017-13229"
          }
        },
        'CVE-2017-13230': {
          '2018-02:1_1': {
            "ASB": "2018-02", "published_date": "2018-01-01", "android_id": "A-87713100",
            "CVE": "CVE-2017-13230"
          }
        },
        'CVE-2017-13231': {
          '2018-03:3': {
            "ASB": "2018-03", "published_date": "2018-02-01", "android_id": "A-97713100", 
            "CVE": "CVE-2017-13231"
          }
        }
      };
      const versionHistory = "1_1";
      const cveTree = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1", "android_id": "A-67713100",
          "CVE": "CVE-2017-13228"
        }, 
        'CVE-2017-13229': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1", "android_id": "A-77713100",
          "CVE": "CVE-2017-13229"
        },
        'CVE-2017-13230': {
          "ASB": "2018-02", "published_date": "2018-01-01","BulletinVersion": "1_1", "android_id": "A-87713100",
          "CVE": "CVE-2017-13230"
        },
        'CVE-2017-13231': {
          "ASB": "2018-03", "published_date": "2018-02-01", "BulletinVersion": "3", "android_id": "A-97713100",
          "CVE": "CVE-2017-13231"
        }
    };
      const jsonData = {
        'CVE-2017-13229': {
            "CVE": "CVE-2017-13229","ASB": "2018-02", "published_date": "2018-01-01", "android_id": "A-77713100", 
            "BulletinVersion": "1_1"
        },
        'CVE-2017-13230': {
            "CVE":"CVE-2017-13230", "ASB": "2018-02", "published_date": "2018-01-01", "android_id": "A-87713100" , 
            "BulletinVersion":"1_1"
        },
      };

      const outputData = myFunctions.buildCVEHistoryTree(tree, versionHistory, cveTree, jsonData);
      const composedSetMap = new Map ();

      const cveIDSet1 = ["2018-02:1", {"ASB": "2018-02", "published_date": "2018-01-01", "android_id": "A-67713100",
                        "CVE": "CVE-2017-13228"}];
      composedSetMap.set("CVE-2017-13228", cveIDSet1);

      const cveIDSet2 = ["2018-02:1", {"ASB": "2018-02", "published_date":"2018-01-01", "android_id": "A-77713100",
                        "CVE": "CVE-2017-13229"}];
      composedSetMap.set("CVE-2017-13229", cveIDSet2);

      const cveIDSet3 = ["2018-02:1_1", {"ASB": "2018-02", "published_date": "2018-01-01", "android_id": "A-87713100",
                        "CVE": "CVE-2017-13230"}];
      composedSetMap.set("CVE-2017-13230", cveIDSet3);

      const cveIDSet4 = ["2018-03:3", {"ASB": "2018-03", "published_date": "2018-02-01", "android_id": "A-97713100", 
                        "CVE": "CVE-2017-13231"}];
      composedSetMap.set("CVE-2017-13231", cveIDSet4);

      const composedUpdateMap = new Map ();

      const cveIDUpdate1 = ["2018-02:1_1", {"published_date":"2018-01-01", "CVE":"CVE-2017-13229", "ASB": "2018-02", 
                           "android_id": "A-77713100"}];
      composedUpdateMap.set("CVE-2017-13229", cveIDUpdate1);

      const composedArray = [composedSetMap, composedUpdateMap];

      chai.assert.deepEqual(outputData, composedArray);
    });
  });

  describe('check version num for cve tree with blank cve tree', () => {
    it('should return true', () => {
      const data = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1", "android_id": "A-67713100",
          "CVE": "CVE-2017-13228"
        }
      };
      const result = null;
      const versionNum = "1";

      const outputData = myFunctions.buildCVETree(data, versionNum, result);
      const composedData = true;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check new version valid for cve tree', () => {
    it('should return true', () => {
      const data = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "2", "android_id": "A-67713100",
          "CVE": "CVE-2017-13228"
        }
      };
      const result = {'CVE-2017-13228': {
        "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1", "android_id": "A-67713100",
        "CVE": "CVE-2017-13228"
      }
    };
      const versionNum = "2";

      const outputData = myFunctions.buildCVETree(data, versionNum, result);
      const composedData = true;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

  describe('check old version num for cve tree', () => {
    it('should return false', () => {
      const data = {
        'CVE-2017-13228': {
          "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "1", "android_id": "A-67713100",
          "CVE": "CVE-2017-13228"
        }
      };
      const result = {'CVE-2017-13228': {
        "ASB": "2018-02", "published_date": "2018-01-01", "BulletinVersion": "2", "android_id": "A-67713100",
        "CVE": "CVE-2017-13228"
      }
    };
      const versionNum = "1";

      const outputData = myFunctions.buildCVETree(data, versionNum, result);
      const composedData = false;

      chai.assert.deepEqual(outputData, composedData);
    });
  });

});
