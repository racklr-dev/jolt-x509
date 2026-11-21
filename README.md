# jolt-x509

A minimal DER (X.690) codec and X.509 Name / Validity / AlgorithmIdentifier /
Certificate parsing for jolt. Extracted from the Merkle Tree Certificates work
for reuse by anything that needs DER or X.509 on jolt.

Run tests:

    for t in test/jolt/*_test.clj; do jolt run "$t"; done
