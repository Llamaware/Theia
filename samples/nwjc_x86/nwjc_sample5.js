function outerFunction(x) {
  function innerFunction(y) {
    return x * y;
  }
  return innerFunction;
}
