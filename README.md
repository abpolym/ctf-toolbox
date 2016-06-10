# CTF Toolbox

This is a repo containing various tools that can be helpful at solving CTF challenges.

Currently, this repo contains:

* [format-dump](./format-dump) - Given a format vulnerability, dump the stack `n` times repeatedly to see canaries, addresses etc. (currently you have to edit the script to fit your needs, e.g. the readuntil arguments, architecture 64bit/32bit)
* [rsasolve](./rsasolve) - Module to crack RSA given different szenarios, such as the HASTAD Broadcast Attack, Wiener Attack, Fermat's Little Theorem etc.. See its docu which szenario applies and which parameters you need :)
