export function checkCVEValidity(ID: any): boolean {
  const regex = /^CVE-\d{4}-\d{3,7}$/;
  if (!regex.test(ID)) {
    return false;
  }
  return true;
}

export function checkBulletinIDValidity(ID: any): boolean {
  const regex = /^(\d{4}-\d{2})$/g;
  if (!regex.test(ID)) {
    return false;
  }
  return true;
}

export function checkVersionIDValidity(version: any): boolean {
  const regex = /^(\d{1}(_\d{1})?)$/g;
  if (!regex.test(version)) {
    const underscoreArray = version.match(/_/g);
    if (underscoreArray) {
      const underscoreCount = underscoreArray.length;
      const idVersionArray = version.split("_");
      if (underscoreCount === 1) {
        if (idVersionArray[1].length === 1) {
          return true;
        }
      }
    }
    return false;
  }
  return true;
}

export function checkSPLValidity(ID: any): boolean {
  const regex = /^(\d{4}-\d{2}-\d{2})$/g;
  if (!regex.test(ID)) {
    return false;
  }
  return true;
}

export function checkAndroidVersionValidity(ID: any): boolean {
  const regex = /^(\d{1}_\d{1}(_\d{1})?)$/g;
  if (!regex.test(ID)) {
    const underscoreArray = ID.match(/_/g);
    if (underscoreArray) {
      const underscoreCount = underscoreArray.length;
      const idAndroidArray = ID.split("_");
      if (underscoreCount === 3) {
        if (idAndroidArray[3] === 1) {
          return true;
        }
      }
    }
    return false;
  }
  return true;
}