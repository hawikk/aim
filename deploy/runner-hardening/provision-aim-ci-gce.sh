#!/usr/bin/env bash
# provision (or re-document) the network-isolated aim-ci runner on GCE.
# Requires: gcloud auth, compute.admin on your-gcp-project, gh auth.
set -euo pipefail
PROJECT="${PROJECT:-your-gcp-project}"
ZONE="${ZONE:-us-central1-a}"
NAME="${NAME:-aim-ci-runner}"
echo "Describe existing instance (if any):"
gcloud compute instances describe "$NAME" --project="$PROJECT" --zone="$ZONE" \
  --format='yaml(name,status,machineType,networkInterfaces,labels)' || true
echo
echo "Online runners:"
gh api repos/hawikk/aim/actions/runners \
  --jq '.runners[] | {name,status,labels:[.labels[].name]}'
