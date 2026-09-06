# Post-refactor-230 architecture

This wave converges **13 outer donors** over the immutable post-refactor-229 baseline. It accounts for **5,001 files**, **2,094 normalized directory/root Merkle records**, **20,744 indexed definitions**, **67 archived symlinks**, and **554 module/subtree groups**.

The target retains one authority per responsibility. New donor-derived semantics are placed into bounded read-only planning/evidence owners for Tor bridge selection, Tor bootstrap readiness, control-paired censorship evidence, DTLS policy, phantom endpoint selection, and metadata-only flow filtering. Active CDN scanning is hardened by public-address admission, while the existing KCP smux owner gains explicit v1/frame/buffer/keepalive policy.

Large donor runtimes such as active TLS interception, Tor process/control, BridgeDB distribution services, Conjure registration/stations, arbitrary QuickJS execution, and alternate scanner/proxy engines remain non-authoritative.
