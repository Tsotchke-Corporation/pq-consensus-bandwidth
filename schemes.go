package main

import (
	"fmt"
	"sort"
	"strings"
)

// Scheme is a signature scheme described only by the two numbers that change
// consensus message size: the serialized signature length and the serialized
// public key length. Nothing here depends on the algorithm itself — a vote's
// marshaled size is a function of how many bytes the signature occupies, not
// of what those bytes mean. That is what lets this tool measure a scheme it
// has no implementation of.
type Scheme struct {
	Name        string
	SigBytes    int
	PubKeyBytes int
	// Variable marks schemes whose signatures are not a fixed length, where
	// SigBytes is the figure the scheme's authors publish for planning.
	Variable bool
	Note     string
}

// schemes are the parameter sets a chain realistically evaluates. Sizes are the
// published serialized lengths from the relevant standard.
var schemes = []Scheme{
	{
		Name: "ed25519", SigBytes: 64, PubKeyBytes: 32,
		Note: "classical baseline, not post-quantum",
	},
	{
		Name: "ml-dsa-44", SigBytes: 2420, PubKeyBytes: 1312,
		Note: "FIPS 204, NIST security category 2",
	},
	{
		Name: "ml-dsa-65", SigBytes: 3309, PubKeyBytes: 1952,
		Note: "FIPS 204, NIST security category 3",
	},
	{
		Name: "ml-dsa-87", SigBytes: 4627, PubKeyBytes: 2592,
		Note: "FIPS 204, NIST security category 5",
	},
	{
		Name: "falcon-512", SigBytes: 666, PubKeyBytes: 897, Variable: true,
		Note: "compressed signatures vary in length; 666 B is the published average, 752 B the practical maximum",
	},
	{
		Name: "falcon-1024", SigBytes: 1280, PubKeyBytes: 1793, Variable: true,
		Note: "compressed signatures vary in length; 1280 B is the published average",
	},
	{
		Name: "slh-dsa-128s", SigBytes: 7856, PubKeyBytes: 32,
		Note: "FIPS 205, small variant: tiny keys, very large signatures",
	},
	{
		Name: "slh-dsa-128f", SigBytes: 17088, PubKeyBytes: 32,
		Note: "FIPS 205, fast variant: signatures larger still",
	},
	{
		Name: "composite-ed25519-ml-dsa-65", SigBytes: 3381, PubKeyBytes: 1992,
		Note: "hybrid: both limbs carried and both required, plus an 8-byte algorithm tag on each of the signature and the key",
	},
}

func lookupScheme(name string) (Scheme, error) {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, s := range schemes {
		if s.Name == want {
			return s, nil
		}
	}
	names := make([]string, 0, len(schemes))
	for _, s := range schemes {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return Scheme{}, fmt.Errorf("unknown scheme %q; known schemes: %s", name, strings.Join(names, ", "))
}
