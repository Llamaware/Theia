const FONT_TYPES = [".ttf", ".otf"];
const LANG_ORDERING = ["english", "korean"];

Lang.search = function () {
  let langDirPath = "/languages/";
  let langFolders = ["folder1"];
  this.list = {};
  for (let folderIndex = 0; folderIndex < 1; folderIndex++) {
    let folderPath = langFolders[folderIndex];
    for (let fontFile of FONT_TYPES) {
      let fontFileName = Utils.basename(fontFile);
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