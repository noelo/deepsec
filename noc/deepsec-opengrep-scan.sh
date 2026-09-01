#!/bin/sh -e
cd $REPO_DIR
opengrep scan --gitlab-sast --gitlab-sast-output $WORK_DIR/$PROJECT_ID.opengrep.json