# Go Style Guide for LumiNet

1. Follow standard `gofmt` and `go vet` rules.
2. Use §8 LumiNet naming conventions (snake_case filenames, no vendor-prefixed function exports).
3. Handle errors explicitly; do not swallow errors silently.
4. Pass `context.Context` as the first argument in IO and database methods.
5. Use `modernc.org/sqlite` for CGO-free database operations.
