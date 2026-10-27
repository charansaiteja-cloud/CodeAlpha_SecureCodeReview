# Findings Summary

The deliberately insecure sample contains SQL string concatenation, shell
execution with shell=True, unsafe pickle deserialization, a fictional
password-like placeholder, and verbose exception disclosure. These are
source-level review targets. Confirm exact locations and tool detections
from local output before claiming any scanner detected them.
