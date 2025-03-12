// Define a minimal Utils object with "ext" and "filename" functions.
var Utils = {
  // Returns the file extension (including the dot) from a filename string.
  ext: function(fileName) {
    var dotIndex = fileName.lastIndexOf(".");
    return dotIndex === -1 ? "" : fileName.substring(dotIndex);
  },
  // Returns the base file name from a path.
  filename: function(path) {
    // Split on both forward and back slashes.
    var parts = path.split(/[\/\\]/);
    return parts[parts.length - 1];
  }
};

// Define the Crypto object with a dummy guardValue, mask, and dekit functions.
var Crypto = {
  guardValue: 123,
  
  // Mask function: decodes the file name, extracts its base name, converts it to uppercase,
  // then computes a mask value by left-shifting and XOR-ing each character's code.
  mask: function(encodedFileName) {
    var maskValue = 0;
    // Decode the file name and get the base name.
    var fileName = Utils.filename(decodeURIComponent(encodedFileName)).toUpperCase();
    for (var i = 0; i < fileName.length; i++) {
      var character = fileName.charAt(i);
      maskValue = (maskValue << 1) ^ character.charCodeAt(0);
    }
    return maskValue;
  },
  
  // The dekit function with readable variable names.
  dekit: function(inputBuffer, fileName, guardValue) {
    // Set default guardValue if undefined.
    if (guardValue === undefined) {
      guardValue = -1;
    }
    
    // Validate input.
    if (!inputBuffer || inputBuffer.length < 1 || this.guardValue !== guardValue || Utils.ext(fileName).toLowerCase() !== ".k9a") {
      return inputBuffer;
    }
    
    // Convert input buffer to a Uint8Array.
    var byteArray = new Uint8Array(inputBuffer);
    
    // The first byte indicates the header length.
    var headerLength = byteArray[0];
    
    // The byte following the header defines the number of bytes to process.
    var processLength = byteArray[1 + headerLength];
    
    // The data to process starts after the header and the length byte.
    var dataSubarray = byteArray.subarray(2 + headerLength);
    
    // Get an initial mask value from the file name.
    var maskValue = Crypto.mask(fileName);
    
    // If processLength is zero, process the entire data subarray.
    if (processLength === 0) {
      processLength = dataSubarray.length;
    }
    
    // Create a copy of the data to work on.
    var outputArray = new Uint8Array(dataSubarray.length);
    outputArray.set(dataSubarray);
    
    // Process each byte: XOR with the mask value, then update the mask.
    for (var i = 0; i < processLength; i++) {
      var currentByte = dataSubarray[i];
      outputArray[i] = (currentByte ^ maskValue) % 256;
      maskValue = (maskValue << 1) ^ currentByte;
    }
    
    // Return the processed buffer.
    return outputArray.buffer;
  }
};

// Sample usage:
// Create a dummy ArrayBuffer (for example purposes)
var dummyData = new Uint8Array([2, 5, 10, 20, 30, 40, 50]).buffer;
// Use the dekit function with a file name ending in ".k9a" and the proper guardValue.
var resultBuffer = Crypto.dekit(dummyData, "example.k9a", 123);
console.log(new Uint8Array(resultBuffer));
