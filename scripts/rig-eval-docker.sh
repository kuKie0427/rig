#!/bin/bash
# A simple script that:
# - mounts your rig config into the docker container
# - mounts the ./eval_results folder
#    - (which should be a symlink to path ./eval-results/eval_results
#       where ./eval-results is a worktree of the git branch of the same name)
# - runs the rig-eval command
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
GIT_ROOT_DIR=$SCRIPT_DIR/..
docker run \
    -v ~/.config/rig:/home/appuser/.config/rig \
    -v $GIT_ROOT_DIR/eval_results:/app/eval_results \
    rig-eval \
    --timeout 60 \
    $@
