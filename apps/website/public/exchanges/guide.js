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

  // Address check: the x-coordinate of a secp256k1 point (x < p and x^3 + 7 is
  // a square mod p), written as 64 lowercase hex characters or as a bech32m
  // (BIP-350) address with the prefix cmfd and no witness-version symbol. The
  // rules run in the order the node's decoder applies them, so the messages
  // match the wallet's validateaddress.
  var P = (1n << 256n) - (1n << 32n) - 977n;
  var HRP = 'cmfd';
  var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var BECH32M_CONST = 0x2bc830a3;
  function polymod(values) {
    var generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var checksum = 1;
    values.forEach(function (value) {
      var top = checksum >>> 25;
      checksum = ((checksum & 0x1ffffff) << 5) ^ value;
      for (var i = 0; i < 5; i++) if ((top >>> i) & 1) checksum ^= generator[i];
    });
    return checksum;
  }
  function hrpExpand(hrp) {
    var codes = hrp.split('').map(function (c) { return c.charCodeAt(0); });
    return codes.map(function (c) { return c >> 5; }).concat([0], codes.map(function (c) { return c & 31; }));
  }
  function toHex(key) {
    return key.map(function (byte) { return (byte < 16 ? '0' : '') + byte.toString(16); }).join('');
  }
  function encode(key) {
    var symbols = [], buffer = 0, bits = 0;
    key.forEach(function (byte) {
      buffer = ((buffer << 8) | byte) & 0xfff;
      bits += 8;
      while (bits >= 5) { bits -= 5; symbols.push((buffer >> bits) & 31); }
    });
    if (bits > 0) symbols.push((buffer << (5 - bits)) & 31);
    var value = polymod(hrpExpand(HRP).concat(symbols, [0, 0, 0, 0, 0, 0])) ^ BECH32M_CONST;
    for (var i = 0; i < 6; i++) symbols.push((value >> (5 * (5 - i))) & 31);
    return HRP + '1' + symbols.map(function (symbol) { return CHARSET[symbol]; }).join('');
  }
  // Returns the key bytes, or a string saying what is wrong.
  function decodeBech32m(text) {
    if (text.length > 90) return 'The address is too long.';
    if (/[^\x21-\x7e]/.test(text)) return 'The address contains a character that is not used in addresses.';
    if (/[a-z]/.test(text) && /[A-Z]/.test(text)) return 'The address mixes upper and lower case. Use all lowercase or all uppercase.';
    var lower = text.toLowerCase();
    var separator = lower.lastIndexOf('1');
    var hrp = lower.slice(0, separator), data = lower.slice(separator + 1);
    if (hrp === '' || data.length < 6) return 'The address has the wrong length.';
    var symbols = [];
    for (var i = 0; i < data.length; i++) {
      var symbol = CHARSET.indexOf(data[i]);
      if (symbol < 0) return 'The address contains a character that is not used in addresses.';
      symbols.push(symbol);
    }
    if (polymod(hrpExpand(hrp).concat(symbols)) !== BECH32M_CONST) return 'The checksum does not match: the address is mistyped or incomplete.';
    if (hrp !== HRP) return 'This address is for another network: expected cmfd1…, found ' + hrp + '1…';
    symbols = symbols.slice(0, -6);
    if (symbols.length !== 52) return 'The address does not hold a 32-byte key.';
    var key = [], buffer = 0, bits = 0;
    symbols.forEach(function (value) {
      buffer = ((buffer << 5) | value) & 0xfff;
      bits += 5;
      if (bits >= 8) { bits -= 8; key.push((buffer >> bits) & 0xff); }
    });
    if (bits !== 4 || (buffer & 0xf) !== 0) return 'The address does not hold a 32-byte key.';
    return key;
  }
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
    var key, checksummed = false;
    if (/^[0-9a-fA-F]+$/.test(value)) {
      if (value.length !== 64) return ['no', 'Invalid', 'Expected a cmfd1… address or 64 hex characters; this has ' + value.length + '.'];
      if (/[A-F]/.test(value)) return ['no', 'Invalid', 'Use lowercase hex; uppercase letters are not accepted.'];
      key = value.match(/../g).map(function (pair) { return parseInt(pair, 16); });
    } else if (value.indexOf('1') >= 0) {
      key = decodeBech32m(value);
      if (typeof key === 'string') return ['no', 'Invalid', key];
      checksummed = true;
    } else {
      return ['no', 'Invalid', 'Expected a cmfd1… address or 64 lowercase hex characters.'];
    }
    var x = BigInt('0x' + toHex(key));
    if (x >= P) return ['no', 'Invalid', 'The value is outside the curve’s field.'];
    var y2 = (power(x, 3n, P) + 7n) % P;
    if (y2 !== 0n && power(y2, (P - 1n) / 2n, P) !== 1n) return ['no', 'Invalid', 'Not a point on secp256k1; this is probably a typo.'];
    if (checksummed) return ['ok', 'Valid', 'Valid checksummed address. The same key in hex: ' + toHex(key)];
    return ['ok', 'Valid', 'Well-formed hex address. Hex has no checksum, so a mistyped address can also be well-formed; compare it with the original. The same key, checksummed: ' + encode(key)];
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
