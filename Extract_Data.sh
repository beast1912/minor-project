#!/bin/bash

# set the directory where the zip files are located
dir="/home/sd-work/Code/Minor-Project/LUFlow"

# set the directory where the extracted contents will be placed
output_dir="/home/sd-work/Code/Minor-Project/Data"

# loop through all the zip files in the directory and extract them
for file in $(find "$dir" -name "*.zip"); do
    # extract the contents of the zip file into the output directory
    unzip -j "$file" -d "$output_dir"
done
