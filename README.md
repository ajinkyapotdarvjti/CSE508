CSE508
======

Network Security

The Content Security Policy draft standard defines script nonces that can be used to prevent cross-site scripting (XSS) attacks. Design and implement an Apache module to automatically insert script nonces into CSPs and web pages served by Apache.

The primary dsign question is: which scripts should have a script nonce added to them? One method would be to have a server-side nonce that gets replaced with a client-side nonce that gets changed every time. Thus a web page with an injected script would look like this, before processing:

<script script-nonce="some secret value">
  /* Valid script here */
</scipt>
<script>
  /* evil injected script here */
</script>

The Apache module would be configured to look for scripts with "some secret value" and replace it with a fresh, random value that it also placed inside the CSP:

<script script-nonce="some fresh random value">
  /* Valid script here */
</scipt>
<script>
  /* evil injected script here */
</script>

