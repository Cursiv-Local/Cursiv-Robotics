# Sample evidence package (SYNTHETIC)

`sample-buoy-1-package/` is a Cursiv Robotics evidence package (contract version 1) from a 20-minute simulated buoy
mission. `trust.json` holds the public keys that signed it. They are **simulation keys derived from a
public seed**: use them only for testing, never to trust real evidence.

```
cursiv-verify package sample-buoy-1-package --trust trust.json --science
py -m cursiv_integration import sample-buoy-1-package --workspace ./workspace --trust trust.json
```
