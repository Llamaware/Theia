// A small JavaScript example with nested functions
function processNumbers(arr) {
  // A nested helper function to double a number
  function double(num) {
    return num * 2;
  }
  
  // Process the array using an anonymous function which itself nests a function
  let result = arr.map(function(n) {
    // A further nested function to add a constant value
    function addConstant(x) {
      return x + 10;
    }
    return addConstant(double(n));
  });
  
  return result;
}

console.log(processNumbers([1, 2, 3, 4])); // Expected output: [12, 14, 16, 18]
