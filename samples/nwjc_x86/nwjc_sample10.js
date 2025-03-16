function computeResult(input) {
  try {
    // Validate input: must be a string.
    if (typeof input !== 'string') {
      throw new TypeError("Input must be a string");
    }
    // Attempt to parse the JSON.
    let data = JSON.parse(input);

    // Nested try/catch to simulate additional exception handling.
    try {
      // Let's say processData may throw an exception if data is malformed.
      let result = processData(data);
      return result;
    } catch (innerError) {
      console.error("Error processing data:", innerError);
      return null;
    }
  } catch (error) {
    console.error("Failed to compute result:", error);
    // Optionally, rethrow or handle the error.
    throw error;
  } finally {
    console.log("Computation finished, cleaning up...");
  }
}

function processData(data) {
  // Example processing that might throw.
  if (!data.value) {
    throw new Error("Missing 'value' property in data");
  }
  // Just return a computed result.
  return data.value * 2;
}

// Test the function with valid and invalid inputs.
try {
  console.log("Result:", computeResult('{"value": 10}'));
} catch (e) {
  console.error("Caught error in main:", e);
}

try {
  console.log("Result:", computeResult(123)); // This will throw.
} catch (e) {
  console.error("Caught error in main:", e);
}
