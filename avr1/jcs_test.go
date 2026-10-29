package avr1

import "testing"

func TestJCSRFC8785CanonicalizationExample(t *testing.T) {
	input := []byte("{\"numbers\":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\",\"literals\":[null,true,false]}")
	want := "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
	got, err := canonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical json mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestJCSRFC8785NumberSerializationSamples(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "positive zero", in: `0`, want: `0`},
		{name: "negative zero", in: `-0`, want: `0`},
		{name: "min positive", in: `5e-324`, want: `5e-324`},
		{name: "min negative", in: `-5e-324`, want: `-5e-324`},
		{name: "max positive", in: `1.7976931348623157e+308`, want: `1.7976931348623157e+308`},
		{name: "max negative", in: `-1.7976931348623157e+308`, want: `-1.7976931348623157e+308`},
		{name: "max safe plus one", in: `9007199254740992`, want: `9007199254740992`},
		{name: "min safe minus one", in: `-9007199254740992`, want: `-9007199254740992`},
		{name: "large integer decimal", in: `295147905179352830000`, want: `295147905179352830000`},
		{name: "below 1e23", in: `9.999999999999997e+22`, want: `9.999999999999997e+22`},
		{name: "one e23", in: `1e+23`, want: `1e+23`},
		{name: "above 1e23", in: `1.0000000000000001e+23`, want: `1.0000000000000001e+23`},
		{name: "below 1e21 a", in: `999999999999999700000`, want: `999999999999999700000`},
		{name: "below 1e21 b", in: `999999999999999900000`, want: `999999999999999900000`},
		{name: "one e21", in: `1e+21`, want: `1e+21`},
		{name: "below one e minus six", in: `9.999999999999997e-7`, want: `9.999999999999997e-7`},
		{name: "one e minus six", in: `0.000001`, want: `0.000001`},
		{name: "fraction a", in: `333333333.3333332`, want: `333333333.3333332`},
		{name: "fraction b", in: `333333333.33333325`, want: `333333333.33333325`},
		{name: "fraction c", in: `333333333.3333333`, want: `333333333.3333333`},
		{name: "fraction d", in: `333333333.3333334`, want: `333333333.3333334`},
		{name: "fraction e", in: `333333333.33333343`, want: `333333333.33333343`},
		{name: "negative small decimal", in: `-0.0000033333333333333333`, want: `-0.0000033333333333333333`},
		{name: "large fraction", in: `1424953923781206.2`, want: `1424953923781206.2`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalizeJSON([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("canonical number = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestJCSPropertySortsByUTF16CodeUnits(t *testing.T) {
	input := []byte("{\"€\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\",\"1\":\"One\",\"😀\":\"Emoji: Grinning Face\",\"\\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\"}")
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := canonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical sort mismatch:\n got: %s\nwant: %s", got, want)
	}
}
