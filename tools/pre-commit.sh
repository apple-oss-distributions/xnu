#!/bin/sh
set -e

# Abort a commit if the code style is incorrect.

# Get a list of paths with staged changes.
FILES=$(git diff --staged --name-only --diff-filter=d)
# Check the paths for style issues.
RESULT=0
if [ ! -z "$FILES" ]; then
    # Stash any unstaged changes.
    git stash --quiet --keep-index
    ./tools/uncrustify.sh $FILES || RESULT=$?
    # Restore the unstaged changes.
    git stash pop --quiet
fi
exit $RESULT
