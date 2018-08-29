set -e

echo "Getting tools..."

go get github.com/golang/mock/gomock
go install github.com/golang/mock/mockgen

SCRIPT_DIR=$(dirname "$0")

echo "Building mocks..."
# Add more lines for new files
mockgen -destination "$SCRIPT_DIR/mock_p11.go" -package mocks -source "$SCRIPT_DIR/../p11.go" TokenCtx

echo "Done"
