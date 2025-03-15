function isValidPassword(password) {
    // Rule 1: Must be 6 digits long
    if (password.length !== 6 || isNaN(password)) {
        return false;
    }

    // Rule 2: Sum of digits must be even
    const digits = password.split('').map(Number);
    const sum = digits.reduce((acc, digit) => acc + digit, 0);
    if (sum % 2 !== 0) {
        return false;
    }

    // Rule 3: XOR of digits must equal 3
    const xorResult = digits.reduce((acc, digit) => acc ^ digit, 0);
    if (xorResult !== 3) {
        return false;
    }

    // Rule 4: No repeated digits
    const uniqueDigits = new Set(digits);
    if (uniqueDigits.size !== digits.length) {
        return false;
    }

    // If all rules are satisfied, return true
    return true;
}

function checkPassword() {
    // Prompt the user for a password
    const userInput = prompt("Please enter your serial code (6 digits only):");

    // Validate the password using the rules
    if (isValidPassword(userInput)) {
        alert("Access granted!");
    } else {
        alert("Access denied! Invalid serial code.");
    }
}