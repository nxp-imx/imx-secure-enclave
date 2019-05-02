#!/bin/bash

lavacli --identity $1 jobs list --limit 100 | grep -f LAVA_JOBS

