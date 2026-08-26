#!/bin/bash

for i in {0..14}; do
    python3 ./get_python_files.py "$i"
done
