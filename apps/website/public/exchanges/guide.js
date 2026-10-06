(function () {
  // Copy buttons: copy the code block's text, falling back to selecting it.
  document.querySelectorAll('.code').forEach(function (block) {
    var button = block.querySelector('.copy');
    var pre = block.querySelector('pre');
    if (!button || !pre) return;
    button.addEventListener('click', function () {
      var text = pre.innerText;
      var done = function () { button.textContent = 'Copied'; setTimeout(function () { button.textContent = 'Copy'; }, 1600); };
      var select = function () {
        var range = document.createRange();
        range.selectNodeContents(pre);
        var selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        button.textContent = 'Selected';
        setTimeout(function () { button.textContent = 'Copy'; }, 1600);
      };
      try {
        navigator.clipboard.writeText(text).then(done, select);
      } catch (error) { select(); }
    });
  });

  // Address check: 64 lowercase hex characters encoding the x-coordinate of a
  // secp256k1 point (x < p and x^3 + 7 is a square mod p), the same rule the
  // wallet's validateaddress applies.
  var P = (1n << 256n) - (1n << 32n) - 977n;
  function power(base, exponent, modulus) {
    var result = 1n;
    base %= modulus;
    while (exponent > 0n) {
      if (exponent & 1n) result = (result * base) % modulus;
      base = (base * base) % modulus;
      exponent >>= 1n;
    }
    return result;
  }
  function verdict(text) {
    var value = text.trim();
    if (value === '') return ['idle', '', 'Paste an address to check it.'];
    if (value.length !== 64) return ['no', 'Invalid', 'Expected 64 characters, got ' + value.length + '.'];
    if (/[A-F]/.test(value)) return ['no', 'Invalid', 'Use lowercase hex; uppercase letters are not accepted.'];
    if (!/^[0-9a-f]{64}$/.test(value)) return ['no', 'Invalid', 'Only the characters 0-9 and a-f are allowed.'];
    var x = BigInt('0x' + value);
    if (x >= P) return ['no', 'Invalid', 'The value is outside the curve’s field.'];
    var y2 = (power(x, 3n, P) + 7n) % P;
    if (y2 !== 0n && power(y2, (P - 1n) / 2n, P) !== 1n) return ['no', 'Invalid', 'Not a point on secp256k1; this is probably a typo.'];
    return ['ok', 'Valid', 'Well-formed address. A mistyped address can also be well-formed, so compare it with the original.'];
  }
  var input = document.getElementById('address-input');
  var output = document.getElementById('address-verdict');
  function render() {
    var result = verdict(input.value);
    output.className = 'verdict ' + result[0];
    output.textContent = '';
    if (result[1]) {
      var pill = document.createElement('span');
      pill.className = 'pill';
      pill.textContent = result[1];
      output.appendChild(pill);
    }
    var message = document.createElement('span');
    message.textContent = result[2];
    output.appendChild(message);
  }
  input.addEventListener('input', render);
  render();
})();
