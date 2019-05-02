#!/bin/bash

# Print all commands
set +x

wget --no-check-certificate http://10.0.2.15/seco_test/seco_nvm
mv -f seco_nvm /etc

