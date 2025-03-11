function sampleComplex(n, m) {
    var obj = { x: n, y: m };
    obj.x *= 2;
    obj.y += obj.x;

    if (obj.y < 0) {
        obj.y = -obj.y;
    }

    var str = "Hello" + "World";
    var res = str.length;    // Just messing with the string

    return obj.y + res;
}

function nestedLoops(arr) {
    var sum = 0;
    for (var i = 0; i < arr.length; i++) {
        for (var j = 0; j < arr[i].length; j++) {
            sum += arr[i][j];
        }
    }
    return sum;
}

function multiAssign(a, b) {
    // Some contrived operations 
    var c = a & b;
    var d = a | b;
    var e = (c ^ d) << 2;

    // A random check
    if (e > 50) {
        e -= 10;
    } else {
        e += 10;
    }
    return e;
}
