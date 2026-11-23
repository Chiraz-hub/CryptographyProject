// Cosmetic behaviour only: the server validates everything again.
(function () {
  var alg = document.getElementById('algorithm');
  if (alg) {
    var sizeRow = document.getElementById('size-row');
    var pwRows = document.getElementById('pw-rows');
    var sync = function () {
      sizeRow.classList.toggle('hidden', alg.value === 'chacha20-poly1305');
      var raw = document.querySelector('input[name=key_mode]:checked').value === 'raw';
      pwRows.classList.toggle('hidden', raw);
    };
    alg.addEventListener('change', sync);
    document.querySelectorAll('input[name=key_mode]').forEach(function (r) {
      r.addEventListener('change', sync);
    });
    sync();
  }
  // Loading indicator. A download gives no completion event, so re-enable after a delay.
  document.querySelectorAll('form').forEach(function (f) {
    f.addEventListener('submit', function () {
      var b = f.querySelector('.upload');
      if (!b || !b.value) return;
      var label = b.value;
      b.disabled = true; b.value = 'Working…';
      setTimeout(function () { b.disabled = false; b.value = label; }, 8000);
    });
  });
  var copy = document.getElementById('copy');
  if (copy) {
    copy.addEventListener('click', function () {
      var k = document.getElementById('key'); k.select();
      if (navigator.clipboard) navigator.clipboard.writeText(k.value);
    });
  }
})();
