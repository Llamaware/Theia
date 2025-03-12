// moduleA.js
// This file defines a couple of functions that can be used by other modules.

function greet(name) {
    return "Hello, " + name + "!";
}

function add(a, b) {
    return a + b;
}

nw.Window.get().evalNWBin(null, "www/js/mainB.bin");