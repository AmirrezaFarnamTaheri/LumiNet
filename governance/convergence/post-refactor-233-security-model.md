# Post-refactor-233 security model

The new planners perform no subscription fetch, browser redirect, Tor control, active scan, host inspection, host mutation, traffic shaping, padding generation, GeoIP lookup, or network I/O. Active MITM/CA installation, opaque donor executables, arbitrary exitmap modules, browser-side scanning, mutable public proxy feeds, donor databases and duplicate VPN/Tor/runtime owners remain non-authoritative.
