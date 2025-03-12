// moduleB.js
// This file calls functions defined in moduleA.js.

function sayHelloToPerson(name) {
    // Call the greet function from moduleA.js
    var greeting = greet(name);
    return greeting;
}

function computeSum(x, y) {
    // Call the add function from moduleA.js and then process the result
    var sum = add(x, y);
    return sum * 2;
}
