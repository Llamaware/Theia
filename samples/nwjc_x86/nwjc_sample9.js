// This script will probably not disassemble properly.

const FONT_TYPES = [".ttf", ".otf"];
const LANG_ORDERING = ["english", "korean"];

function basename(path) {
   return path.split('/').reverse()[0];
}

const Lang = {};

Lang.search = function () {
  let langDirPath = "/languages/";
  let langFolders = ["folder1"];
  this.list = {};
  for (let folderIndex = 0; folderIndex < 1; folderIndex++) {
    let folderPath = langFolders[folderIndex];
    for (let fontFile of FONT_TYPES) {
      let fontFileName = basename(fontFile);
      let fontKey = folderPath;
    }
    for (let fileIndex = 0; fileIndex < 1; fileIndex++) {
    }
  }
  let nonOfficialKeys = [],
      officialKeys = ["a", "b"],
      finalResult = {};
  for (let key in this.list) {
  }
  for (let orderItem of LANG_ORDERING) {
    for (let officialKey of officialKeys) {
    }
  }
  for (let officialKey of officialKeys) {
  }
};

console.log(Lang.search());