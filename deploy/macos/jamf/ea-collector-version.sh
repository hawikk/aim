#!/bin/bash
# Jamf Extension Attribute — AI Monitoring Collector Version (AIM-743).
# Data Type: String. Input Type: Script.
# Smart group example: "AI Monitoring Collector Version is 0.1.0"
VERSION_FILE="/etc/aim-collector/version"
if [ -r "$VERSION_FILE" ]; then
  ver="$(tr -d '[:space:]' < "$VERSION_FILE")"
else
  ver="Not Installed"
fi
echo "<result>${ver}</result>"
