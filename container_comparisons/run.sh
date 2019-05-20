OUTPUT_DIR=./bin

pushd $OUTPUT_DIR >> /dev/null

# running test for key is an integer - compares (ordered map, unordered map, array and vector storage)
./int_key_compare

# running test for key is a string - compares (ordered map and unordered map)
./string_key_compare

popd >> /dev/null
