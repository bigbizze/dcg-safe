package version

import "testing"

func TestStringNormalizesBuildVersion(t *testing.T) {
	original := value
	t.Cleanup(func() { value = original })
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "", want: "dev"},
		{input: "(devel)", want: "dev"},
		{input: "dev", want: "dev"},
		{input: "v0.1.0", want: "0.1.0"},
		{input: "0.1.0", want: "0.1.0"},
	} {
		value = test.input
		if got := String(); got != test.want {
			t.Fatalf("String() for %q = %q, want %q", test.input, got, test.want)
		}
	}
}
