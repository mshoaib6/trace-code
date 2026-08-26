#!/bin/bash

for i in {0..14}; do
    python3 ./count_function_calls.py "$i"
done
