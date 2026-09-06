package mobilecore

import (
	"github.com/maybeknott/luminet/internal/runtime/proxy"
	"reflect"
	"testing"
)

func TestMobileConfigRoundTripPreservesEveryEvasionField(t *testing.T) {
	original := populatedEvasionConfigForTest(t)
	mobile := ConfigFromEvasion(original)
	roundTrip := ConfigToEvasion(mobile)
	if !reflect.DeepEqual(roundTrip, original) {
		t.Fatalf("mobile config round trip lost evasion state:\noriginal=%+v\nroundTrip=%+v", original, roundTrip)
	}
}

func populatedEvasionConfigForTest(t *testing.T) proxy.EvasionConfig {
	t.Helper()
	cfg := proxy.EvasionConfig{}
	populateValueForRoundTrip(reflect.ValueOf(&cfg).Elem(), "root")
	return cfg
}

func populateValueForRoundTrip(v reflect.Value, path string) {
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		name := path + "." + v.Type().Field(i).Name
		switch field.Kind() {
		case reflect.Bool:
			field.SetBool(true)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			field.SetInt(int64(i + 1))
		case reflect.Float32, reflect.Float64:
			field.SetFloat(float64(i+1) + 0.25)
		case reflect.String:
			field.SetString(name)
		case reflect.Struct:
			populateValueForRoundTrip(field, name)
		default:
			panic("unsupported evasion config field kind: " + field.Kind().String())
		}
	}
}
